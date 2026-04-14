/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Implements:
 *   - bounded-buffer logging pipeline (producer/consumer)
 *   - multi-container supervisor with namespace isolation
 *   - UNIX domain socket control-plane IPC
 *   - SIGCHLD / SIGINT / SIGTERM handling
 *   - per-container metadata tracking and cleanup
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <sched.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

#define STACK_SIZE (1024 * 1024)
#define CONTAINER_ID_LEN 32
#define CONTROL_PATH "/tmp/mini_runtime.sock"
#define LOG_DIR "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN 256
#define LOG_CHUNK_SIZE 4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT (40UL << 20)
#define DEFAULT_HARD_LIMIT (64UL << 20)
#define DEVICE_NAME "container_monitor"

/* Discard the return value of write() when writing to a client socket.
 * If the client disconnects mid-write the error is intentionally ignored. */
#define write_discard(fd, buf, n) \
    do { if (write((fd), (buf), (n)) < 0) { /* ignored */ } } while (0)

typedef enum {
    CMD_SUPERVISOR = 0,
    CMD_START,
    CMD_RUN,
    CMD_PS,
    CMD_LOGS,
    CMD_STOP
} command_kind_t;

typedef enum {
    CONTAINER_STARTING = 0,
    CONTAINER_RUNNING,
    CONTAINER_STOPPED,
    CONTAINER_KILLED,
    CONTAINER_EXITED
} container_state_t;

typedef struct container_record {
    char id[CONTAINER_ID_LEN];
    pid_t host_pid;
    time_t started_at;
    container_state_t state;
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int exit_code;
    int exit_signal;
    int stop_requested;   /* set before sending SIGTERM/SIGKILL from stop */
    int run_client_fd;    /* client socket fd waiting for run to finish, -1 if none */
    char log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char container_id[CONTAINER_ID_LEN];
    size_t length;
    char data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t items[LOG_BUFFER_CAPACITY];
    size_t head;
    size_t tail;
    size_t count;
    int shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char container_id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    unsigned long soft_limit_bytes;
    unsigned long hard_limit_bytes;
    int nice_value;
} control_request_t;

typedef struct {
    int status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int nice_value;
    int log_write_fd;
} child_config_t;

typedef struct {
    int server_fd;
    int monitor_fd;
    int should_stop;
    pthread_t logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t metadata_lock;
    pthread_cond_t state_change_cond;
    container_record_t *containers;
} supervisor_ctx_t;

/* ---------------------------------------------------------------
 * Producer-thread argument struct.
 * One producer thread is spawned per container; it drains the
 * container's stdout/stderr pipe and pushes chunks into the
 * shared bounded buffer.
 * --------------------------------------------------------------- */
typedef struct {
    int pipe_read_fd;
    char container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *log_buffer;
} producer_args_t;

/* --- Global signal state for the supervisor event loop --- */
static volatile sig_atomic_t g_sigchld_pending = 0;
static volatile sig_atomic_t g_shutdown_pending = 0;

/* --- Global signal state used by the run client --- */
static volatile sig_atomic_t g_run_stop_requested = 0;

static void handle_sigchld(int sig)
{
    (void)sig;
    g_sigchld_pending = 1;
}

static void handle_shutdown(int sig)
{
    (void)sig;
    g_shutdown_pending = 1;
}

static void handle_run_stop(int sig)
{
    (void)sig;
    g_run_stop_requested = 1;
}

static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag,
                          const char *value,
                          unsigned long *target_bytes)
{
    char *end = NULL;
    unsigned long mib;

    errno = 0;
    mib = strtoul(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') {
        fprintf(stderr, "Invalid value for %s: %s\n", flag, value);
        return -1;
    }

    if (mib > ULONG_MAX / (1UL << 20)) {
        fprintf(stderr, "Value for %s is too large: %s\n", flag, value);
        return -1;
    }

    *target_bytes = mib * (1UL << 20);
    return 0;
}

static int parse_optional_flags(control_request_t *req,
                                int argc,
                                char *argv[],
                                int start_index)
{
    int i;

    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long nice_value;

        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }

        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1], &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1], &req->hard_limit_bytes) != 0)
                return -1;
            continue;
        }

        if (strcmp(argv[i], "--nice") == 0) {
            errno = 0;
            nice_value = strtol(argv[i + 1], &end, 10);
            if (errno != 0 || end == argv[i + 1] || *end != '\0' ||
                nice_value < -20 || nice_value > 19) {
                fprintf(stderr,
                        "Invalid value for --nice (expected -20..19): %s\n",
                        argv[i + 1]);
                return -1;
            }
            req->nice_value = (int)nice_value;
            continue;
        }

        fprintf(stderr, "Unknown option: %s\n", argv[i]);
        return -1;
    }

    if (req->soft_limit_bytes > req->hard_limit_bytes) {
        fprintf(stderr, "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }

    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING:
        return "starting";
    case CONTAINER_RUNNING:
        return "running";
    case CONTAINER_STOPPED:
        return "stopped";
    case CONTAINER_KILLED:
        return "killed";
    case CONTAINER_EXITED:
        return "exited";
    default:
        return "unknown";
    }
}

static int bounded_buffer_init(bounded_buffer_t *buffer)
{
    int rc;

    memset(buffer, 0, sizeof(*buffer));

    rc = pthread_mutex_init(&buffer->mutex, NULL);
    if (rc != 0)
        return rc;

    rc = pthread_cond_init(&buffer->not_empty, NULL);
    if (rc != 0) {
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    rc = pthread_cond_init(&buffer->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buffer->not_empty);
        pthread_mutex_destroy(&buffer->mutex);
        return rc;
    }

    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buffer)
{
    pthread_cond_destroy(&buffer->not_full);
    pthread_cond_destroy(&buffer->not_empty);
    pthread_mutex_destroy(&buffer->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buffer)
{
    pthread_mutex_lock(&buffer->mutex);
    buffer->shutting_down = 1;
    pthread_cond_broadcast(&buffer->not_empty);
    pthread_cond_broadcast(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
}

/*
 * Implement producer-side insertion into the bounded buffer.
 * Blocks when the buffer is full until space becomes available or
 * shutdown begins. Returns 0 on success, -1 if shutting down.
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == LOG_BUFFER_CAPACITY && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_full, &buffer->mutex);

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    pthread_cond_signal(&buffer->not_empty);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * Implement consumer-side removal from the bounded buffer.
 * Blocks when empty until data arrives or shutdown begins.
 * Returns 0 on success, -1 when shutting down and the buffer is
 * empty (all remaining work has been drained).
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    pthread_mutex_lock(&buffer->mutex);

    while (buffer->count == 0 && !buffer->shutting_down)
        pthread_cond_wait(&buffer->not_empty, &buffer->mutex);

    if (buffer->count == 0) {
        /* Shutting down and nothing left to consume. */
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    pthread_cond_signal(&buffer->not_full);
    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * Logging consumer thread.
 * Pops log chunks from the bounded buffer, resolves the per-container
 * log-file path, and appends the data. Exits cleanly once the buffer
 * signals shutdown and all remaining items have been drained.
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;

    while (bounded_buffer_pop(&ctx->log_buffer, &item) == 0) {
        char log_path[PATH_MAX] = "";

        /* Resolve log path under the metadata lock so we handle
         * containers that exit before all their output is flushed. */
        pthread_mutex_lock(&ctx->metadata_lock);
        {
            container_record_t *rec = ctx->containers;
            while (rec) {
                if (strncmp(rec->id, item.container_id, CONTAINER_ID_LEN) == 0) {
                    snprintf(log_path, sizeof(log_path), "%s", rec->log_path);
                    break;
                }
                rec = rec->next;
            }
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (log_path[0] != '\0') {
            int fd = open(log_path, O_WRONLY | O_CREAT | O_APPEND, 0644);
            if (fd >= 0) {
                ssize_t w = write(fd, item.data, item.length);
                (void)w;
                close(fd);
            }
        }
    }

    return NULL;
}

/*
 * Producer thread: reads from a container's stdout/stderr pipe and
 * pushes LOG_CHUNK_SIZE-sized chunks into the shared bounded buffer.
 * Exits naturally when the pipe reaches EOF (container exited).
 */
static void *producer_thread_fn(void *arg)
{
    producer_args_t *pargs = (producer_args_t *)arg;
    char buf[LOG_CHUNK_SIZE];
    ssize_t n;

    while ((n = read(pargs->pipe_read_fd, buf, sizeof(buf))) > 0) {
        log_item_t item;
        memset(&item, 0, sizeof(item));
        snprintf(item.container_id, CONTAINER_ID_LEN, "%s", pargs->container_id);
        item.length = (size_t)n;
        memcpy(item.data, buf, (size_t)n);
        if (bounded_buffer_push(pargs->log_buffer, &item) != 0)
            break;
    }

    close(pargs->pipe_read_fd);
    free(pargs);
    return NULL;
}

/*
 * Implement the clone child entrypoint.
 *
 * Outcomes:
 *   - isolated PID / UTS / mount context (via clone flags)
 *   - chroot into container rootfs
 *   - /proc mounted inside container
 *   - stdout / stderr redirected to supervisor logging pipe
 *   - nice value applied
 *   - configured command executed via /bin/sh -c
 */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* Redirect stdout and stderr to the supervisor's logging pipe. */
    if (dup2(cfg->log_write_fd, STDOUT_FILENO) < 0 ||
        dup2(cfg->log_write_fd, STDERR_FILENO) < 0) {
        _exit(1);
    }
    close(cfg->log_write_fd);

    /* Give the container a distinct hostname equal to its ID. */
    if (sethostname(cfg->id, strlen(cfg->id)) != 0)
        perror("sethostname"); /* non-fatal */

    /* Chroot into the container's dedicated rootfs. */
    if (chroot(cfg->rootfs) != 0) {
        perror("chroot");
        _exit(1);
    }
    if (chdir("/") != 0) {
        perror("chdir");
        _exit(1);
    }

    /* Mount /proc so tools like 'ps' work inside the container. */
    mkdir("/proc", 0555); /* ignore error if directory already exists */
    if (mount("proc", "/proc", "proc", 0, NULL) != 0)
        perror("mount proc"); /* non-fatal: best effort */

    /* Apply the requested scheduling priority. */
    if (cfg->nice_value != 0) {
        errno = 0;
        if (nice(cfg->nice_value) == -1 && errno != 0)
            perror("nice"); /* non-fatal */
    }

    /* Execute the command through a shell so that simple shell syntax
     * (pipes, redirects, etc.) works without extra parsing. */
    char *const argv[] = { "/bin/sh", "-c", cfg->command, NULL };
    execv("/bin/sh", argv);
    perror("execv");
    _exit(1);
}

int register_with_monitor(int monitor_fd,
                          const char *container_id,
                          pid_t host_pid,
                          unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    req.soft_limit_bytes = soft_limit_bytes;
    req.hard_limit_bytes = hard_limit_bytes;
    snprintf(req.container_id, sizeof(req.container_id), "%s", container_id);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    snprintf(req.container_id, sizeof(req.container_id), "%s", container_id);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

/* ---------------------------------------------------------------
 * Supervisor helpers
 * --------------------------------------------------------------- */

/* Find a container record by ID (caller must hold metadata_lock). */
static container_record_t *find_container(supervisor_ctx_t *ctx,
                                          const char *id)
{
    container_record_t *rec = ctx->containers;
    while (rec) {
        if (strncmp(rec->id, id, CONTAINER_ID_LEN) == 0)
            return rec;
        rec = rec->next;
    }
    return NULL;
}

/* Find a container record by host PID (caller must hold metadata_lock). */
static container_record_t *find_container_by_pid(supervisor_ctx_t *ctx,
                                                  pid_t pid)
{
    container_record_t *rec = ctx->containers;
    while (rec) {
        if (rec->host_pid == pid)
            return rec;
        rec = rec->next;
    }
    return NULL;
}

/* Reap all exited children, update metadata, and respond to any
 * waiting 'run' clients.  Called from the event loop when
 * g_sigchld_pending is set. */
static void reap_children(supervisor_ctx_t *ctx)
{
    int wstatus;
    pid_t pid;

    while ((pid = waitpid(-1, &wstatus, WNOHANG)) > 0) {
        pthread_mutex_lock(&ctx->metadata_lock);

        container_record_t *rec = find_container_by_pid(ctx, pid);
        if (rec) {
            if (WIFEXITED(wstatus)) {
                rec->exit_code = WEXITSTATUS(wstatus);
                rec->exit_signal = 0;
                rec->state = CONTAINER_EXITED;
            } else if (WIFSIGNALED(wstatus)) {
                rec->exit_code = 0;
                rec->exit_signal = WTERMSIG(wstatus);
                /* Distinguish manual stop from hard-limit kill. */
                if (rec->stop_requested)
                    rec->state = CONTAINER_STOPPED;
                else
                    rec->state = CONTAINER_KILLED;
            }

            /* Respond to any waiting 'run' client. */
            if (rec->run_client_fd >= 0) {
                char msg[256];
                int n;
                if (rec->exit_signal != 0)
                    n = snprintf(msg, sizeof(msg),
                                 "exited: id=%s signal=%d state=%s\n",
                                 rec->id, rec->exit_signal,
                                 state_to_string(rec->state));
                else
                    n = snprintf(msg, sizeof(msg),
                                 "exited: id=%s code=%d state=%s\n",
                                 rec->id, rec->exit_code,
                                 state_to_string(rec->state));
                write_discard(rec->run_client_fd, msg, (size_t)n);
                close(rec->run_client_fd);
                rec->run_client_fd = -1;
            }

            /* Unregister from kernel monitor (best effort). */
            if (ctx->monitor_fd >= 0)
                unregister_from_monitor(ctx->monitor_fd,
                                        rec->id, rec->host_pid);
        }

        pthread_cond_broadcast(&ctx->state_change_cond);
        pthread_mutex_unlock(&ctx->metadata_lock);
    }
}

/* Launch a new container.  Returns 0 on success.
 * Caller must NOT hold metadata_lock. */
static int launch_container(supervisor_ctx_t *ctx,
                            const control_request_t *req,
                            int run_client_fd)
{
    int pipefd[2];
    pid_t pid;
    char *child_stack;
    child_config_t cfg;
    container_record_t *rec;
    producer_args_t *pargs;
    pthread_t prod_tid;
    int clone_flags;

    /* Check for duplicate ID before allocating resources. */
    pthread_mutex_lock(&ctx->metadata_lock);
    if (find_container(ctx, req->container_id)) {
        pthread_mutex_unlock(&ctx->metadata_lock);
        fprintf(stderr, "Container '%s' already exists\n", req->container_id);
        return -1;
    }
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Create the log directory if needed. */
    mkdir(LOG_DIR, 0755);

    /* Create the pipe that will carry the container's stdout/stderr. */
    if (pipe(pipefd) < 0) {
        perror("pipe");
        return -1;
    }

    /* Build the child configuration. */
    memset(&cfg, 0, sizeof(cfg));
    snprintf(cfg.id, CONTAINER_ID_LEN, "%s", req->container_id);
    snprintf(cfg.rootfs, PATH_MAX, "%s", req->rootfs);
    snprintf(cfg.command, CHILD_COMMAND_LEN, "%s", req->command);
    cfg.nice_value = req->nice_value;
    cfg.log_write_fd = pipefd[1];

    /* Allocate the child stack (stack grows downward on x86-64). */
    child_stack = mmap(NULL, STACK_SIZE,
                       PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK,
                       -1, 0);
    if (child_stack == MAP_FAILED) {
        perror("mmap child stack");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid = clone(child_fn, child_stack + STACK_SIZE, clone_flags, &cfg);

    munmap(child_stack, STACK_SIZE);

    if (pid < 0) {
        perror("clone");
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }

    /* Close the write end in the parent; the child owns it. */
    close(pipefd[1]);

    /* Allocate and register container metadata. */
    rec = calloc(1, sizeof(*rec));
    if (!rec) {
        /* Container is running but we can't track it — kill it. */
        kill(pid, SIGKILL);
        close(pipefd[0]);
        return -1;
    }
    snprintf(rec->id, CONTAINER_ID_LEN, "%s", req->container_id);
    rec->host_pid = pid;
    rec->started_at = time(NULL);
    rec->state = CONTAINER_RUNNING;
    rec->soft_limit_bytes = req->soft_limit_bytes;
    rec->hard_limit_bytes = req->hard_limit_bytes;
    rec->exit_code = 0;
    rec->exit_signal = 0;
    rec->stop_requested = 0;
    rec->run_client_fd = run_client_fd;
    snprintf(rec->log_path, sizeof(rec->log_path),
             "%s/%s.log", LOG_DIR, req->container_id);

    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next = ctx->containers;
    ctx->containers = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Register with the kernel memory monitor (optional). */
    if (ctx->monitor_fd >= 0)
        register_with_monitor(ctx->monitor_fd, rec->id, pid,
                              req->soft_limit_bytes, req->hard_limit_bytes);

    /* Start the producer thread that reads from the container pipe. */
    pargs = malloc(sizeof(*pargs));
    if (pargs) {
        pargs->pipe_read_fd = pipefd[0];
        snprintf(pargs->container_id, CONTAINER_ID_LEN, "%s", req->container_id);
        pargs->log_buffer = &ctx->log_buffer;

        if (pthread_create(&prod_tid, NULL, producer_thread_fn, pargs) != 0) {
            free(pargs);
            close(pipefd[0]);
        } else {
            pthread_detach(prod_tid);
        }
    } else {
        close(pipefd[0]);
    }

    return 0;
}

/* Handle one incoming control connection. */
static void handle_connection(supervisor_ctx_t *ctx, int client_fd)
{
    control_request_t req;
    ssize_t n;

    n = read(client_fd, &req, sizeof(req));
    if (n != (ssize_t)sizeof(req)) {
        close(client_fd);
        return;
    }

    switch (req.kind) {
    case CMD_START: {
        int rc = launch_container(ctx, &req, -1);
        char msg[256];
        snprintf(msg, sizeof(msg),
                 rc == 0 ? "OK: container %s started\n"
                         : "ERROR: failed to start %s\n",
                 req.container_id);
        write_discard(client_fd, msg, strlen(msg));
        close(client_fd);
        break;
    }

    case CMD_RUN: {
        /* Keep client_fd open; it will be closed when the container exits. */
        int rc = launch_container(ctx, &req, client_fd);
        if (rc != 0) {
            char msg[256];
            snprintf(msg, sizeof(msg),
                     "ERROR: failed to start %s\n", req.container_id);
            write_discard(client_fd, msg, strlen(msg));
            close(client_fd);
        }
        /* On success the fd ownership was transferred to the container record. */
        break;
    }

    case CMD_PS: {
        char msg[4096];
        int off = 0;
        off += snprintf(msg + off, sizeof(msg) - (size_t)off,
                        "%-16s %-8s %-10s %-20s %s\n",
                        "ID", "PID", "STATE", "STARTED", "LOG");

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = ctx->containers;
        while (rec && off < (int)sizeof(msg) - 1) {
            char tbuf[32];
            struct tm *tm_info = localtime(&rec->started_at);
            strftime(tbuf, sizeof(tbuf), "%Y-%m-%d %H:%M:%S", tm_info);
            off += snprintf(msg + off, sizeof(msg) - (size_t)off,
                            "%-16s %-8d %-10s %-20s %s\n",
                            rec->id, (int)rec->host_pid,
                            state_to_string(rec->state),
                            tbuf, rec->log_path);
            rec = rec->next;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        write_discard(client_fd, msg, (size_t)off);
        close(client_fd);
        break;
    }

    case CMD_LOGS: {
        char log_path[PATH_MAX] = "";

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container(ctx, req.container_id);
        if (rec)
            snprintf(log_path, sizeof(log_path), "%s", rec->log_path);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (log_path[0] == '\0') {
            char msg[128];
            snprintf(msg, sizeof(msg),
                     "ERROR: container '%s' not found\n", req.container_id);
            write_discard(client_fd, msg, strlen(msg));
        } else {
            int fd = open(log_path, O_RDONLY);
            if (fd < 0) {
                char msg[256];
                snprintf(msg, sizeof(msg),
                         "ERROR: cannot open log %s: %s\n",
                         log_path, strerror(errno));
                write_discard(client_fd, msg, strlen(msg));
            } else {
                char buf[4096];
                ssize_t r;
                while ((r = read(fd, buf, sizeof(buf))) > 0)
                    write_discard(client_fd, buf, (size_t)r);
                close(fd);
            }
        }
        close(client_fd);
        break;
    }

    case CMD_STOP: {
        char msg[256];
        int found = 0;

        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container(ctx, req.container_id);
        if (rec && (rec->state == CONTAINER_RUNNING ||
                    rec->state == CONTAINER_STARTING)) {
            rec->stop_requested = 1;
            found = 1;
            kill(rec->host_pid, SIGTERM);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);

        snprintf(msg, sizeof(msg),
                 found ? "OK: SIGTERM sent to %s\n"
                       : "ERROR: container '%s' not found or not running\n",
                 req.container_id);
        write_discard(client_fd, msg, strlen(msg));
        close(client_fd);
        break;
    }

    case CMD_SUPERVISOR:
    default:
        close(client_fd);
        break;
    }
}

/*
 * Implement the long-running supervisor process.
 *
 * Responsibilities:
 *   - create and bind the control-plane UNIX domain socket
 *   - open the kernel memory monitor device
 *   - install SIGCHLD / SIGINT / SIGTERM handlers
 *   - start the logging consumer thread
 *   - run the select-based event loop accepting control requests
 *   - reap children on SIGCHLD
 *   - drain the log buffer and join the logger thread on shutdown
 */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    struct sigaction sa;
    int rc;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;

    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = pthread_cond_init(&ctx.state_change_cond, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_cond_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_cond_destroy(&ctx.state_change_cond);
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    fprintf(stdout, "Supervisor starting (base-rootfs: %s)\n", rootfs);
    fflush(stdout);

    /* 1) Open the kernel memory monitor device (optional). */
    ctx.monitor_fd = open("/dev/" DEVICE_NAME, O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr, "Note: /dev/" DEVICE_NAME " not available (%s); "
                "memory limits disabled\n", strerror(errno));

    /* 2) Create the control UNIX domain socket. */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    unlink(CONTROL_PATH);
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        goto cleanup;
    }
    if (listen(ctx.server_fd, 16) < 0) {
        perror("listen");
        goto cleanup;
    }

    /* 3) Install signal handlers. */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigchld;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_NOCLDSTOP; /* only fire for termination, not stop */
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = handle_shutdown;
    sa.sa_flags = 0;
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* 4) Start the logger consumer thread. */
    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) {
        errno = rc;
        perror("pthread_create logger");
        goto cleanup;
    }

    fprintf(stdout, "Supervisor ready. Control socket: %s\n", CONTROL_PATH);
    fflush(stdout);

    /* 5) Event loop. */
    while (!ctx.should_stop) {
        /* Handle pending signals before blocking. */
        if (g_sigchld_pending) {
            g_sigchld_pending = 0;
            reap_children(&ctx);
        }
        if (g_shutdown_pending) {
            ctx.should_stop = 1;
            break;
        }

        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);

        struct timeval tv;
        tv.tv_sec = 1;
        tv.tv_usec = 0;

        int sel = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }

        if (sel > 0 && FD_ISSET(ctx.server_fd, &rfds)) {
            int client_fd = accept(ctx.server_fd, NULL, NULL);
            if (client_fd >= 0)
                handle_connection(&ctx, client_fd);
            else if (errno != EINTR)
                perror("accept");
        }
    }

    fprintf(stdout, "Supervisor shutting down...\n");
    fflush(stdout);

    /* Send SIGTERM to all running containers. */
    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *rec = ctx.containers;
        while (rec) {
            if (rec->state == CONTAINER_RUNNING ||
                rec->state == CONTAINER_STARTING) {
                rec->stop_requested = 1;
                kill(rec->host_pid, SIGTERM);
            }
            rec = rec->next;
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Reap any remaining children. */
    reap_children(&ctx);

cleanup:
    /* Signal the logger thread to drain and exit. */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    if (ctx.logger_thread)
        pthread_join(ctx.logger_thread, NULL);

    bounded_buffer_destroy(&ctx.log_buffer);

    /* Free container metadata list. */
    pthread_mutex_lock(&ctx.metadata_lock);
    {
        container_record_t *rec = ctx.containers;
        while (rec) {
            container_record_t *next = rec->next;
            if (rec->run_client_fd >= 0)
                close(rec->run_client_fd);
            free(rec);
            rec = next;
        }
        ctx.containers = NULL;
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    if (ctx.server_fd >= 0)
        close(ctx.server_fd);
    unlink(CONTROL_PATH);
    if (ctx.monitor_fd >= 0)
        close(ctx.monitor_fd);

    pthread_cond_destroy(&ctx.state_change_cond);
    pthread_mutex_destroy(&ctx.metadata_lock);

    fprintf(stdout, "Supervisor done.\n");
    return 0;
}

/*
 * CLI client: connect to the supervisor over the UNIX domain control socket,
 * send a control_request_t, then read and print the text response until
 * the server closes the connection.
 *
 * For CMD_RUN the connection stays open until the container exits; the
 * client honours SIGINT/SIGTERM by forwarding a stop request to the
 * supervisor and then continuing to wait for the final status.
 */
static int send_control_request(const control_request_t *req)
{
    int sockfd;
    struct sockaddr_un addr;
    char buf[4096];
    ssize_t n;

    sockfd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (sockfd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect: is the supervisor running?");
        close(sockfd);
        return 1;
    }

    if (write(sockfd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        perror("write");
        close(sockfd);
        return 1;
    }

    if (req->kind == CMD_RUN) {
        /* Install handlers so SIGINT/SIGTERM forwards a stop. */
        struct sigaction sa;
        memset(&sa, 0, sizeof(sa));
        sa.sa_handler = handle_run_stop;
        sigemptyset(&sa.sa_mask);
        sigaction(SIGINT,  &sa, NULL);
        sigaction(SIGTERM, &sa, NULL);

        /* Read with a short timeout so we can check for stop signals. */
        while (1) {
            if (g_run_stop_requested) {
                g_run_stop_requested = 0;
                /* Forward a stop request to the supervisor. */
                int stop_fd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (stop_fd >= 0 &&
                    connect(stop_fd,
                            (struct sockaddr *)&addr, sizeof(addr)) == 0) {
                    control_request_t stop_req;
                    memset(&stop_req, 0, sizeof(stop_req));
                    stop_req.kind = CMD_STOP;
                    snprintf(stop_req.container_id, CONTAINER_ID_LEN,
                             "%s", req->container_id);
                    write_discard(stop_fd, &stop_req, sizeof(stop_req));
                    /* drain the stop-response and discard it */
                    char tbuf[256];
                    while (read(stop_fd, tbuf, sizeof(tbuf)) > 0)
                        ;
                    close(stop_fd);
                } else if (stop_fd >= 0) {
                    close(stop_fd);
                }
            }

            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);
            struct timeval tv;
            tv.tv_sec = 0;
            tv.tv_usec = 200000; /* 200 ms */
            int sel = select(sockfd + 1, &rfds, NULL, NULL, &tv);
            if (sel < 0 && errno == EINTR)
                continue;
            if (sel <= 0)
                continue;

            n = read(sockfd, buf, sizeof(buf) - 1);
            if (n <= 0)
                break;
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }
    } else {
        /* Simple blocking read for all other commands. */
        while ((n = read(sockfd, buf, sizeof(buf) - 1)) > 0) {
            buf[n] = '\0';
            printf("%s", buf);
            fflush(stdout);
        }
    }

    close(sockfd);
    return 0;
}

static int cmd_start(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n",
                argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs, argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command, argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;

    if (parse_optional_flags(&req, argc, argv, 5) != 0)
        return 1;

    return send_control_request(&req);
}

static int cmd_ps(void)
{
    control_request_t req;

    memset(&req, 0, sizeof(req));
    req.kind = CMD_PS;

    return send_control_request(&req);
}

static int cmd_logs(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s logs <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_LOGS;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

static int cmd_stop(int argc, char *argv[])
{
    control_request_t req;

    if (argc < 3) {
        fprintf(stderr, "Usage: %s stop <id>\n", argv[0]);
        return 1;
    }

    memset(&req, 0, sizeof(req));
    req.kind = CMD_STOP;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);

    return send_control_request(&req);
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        usage(argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }

    if (strcmp(argv[1], "start") == 0)
        return cmd_start(argc, argv);

    if (strcmp(argv[1], "run") == 0)
        return cmd_run(argc, argv);

    if (strcmp(argv[1], "ps") == 0)
        return cmd_ps();

    if (strcmp(argv[1], "logs") == 0)
        return cmd_logs(argc, argv);

    if (strcmp(argv[1], "stop") == 0)
        return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}
