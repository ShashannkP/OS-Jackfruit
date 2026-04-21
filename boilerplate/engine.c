/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Implementation by students on top of provided boilerplate.
 *
 * IPC design:
 *   Path A (logging):  container stdout/stderr -> pipe -> producer thread
 *                      -> bounded_buffer -> consumer thread -> log file
 *   Path B (control):  CLI client -> UNIX domain socket -> supervisor
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
#include <sys/mount.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "monitor_ioctl.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                           */
/* ------------------------------------------------------------------ */
#define STACK_SIZE          (1024 * 1024)
#define CONTAINER_ID_LEN    32
#define CONTROL_PATH        "/tmp/mini_runtime.sock"
#define LOG_DIR             "logs"
#define CONTROL_MESSAGE_LEN 256
#define CHILD_COMMAND_LEN   256
#define LOG_CHUNK_SIZE      4096
#define LOG_BUFFER_CAPACITY 16
#define DEFAULT_SOFT_LIMIT  (40UL << 20)
#define DEFAULT_HARD_LIMIT  (64UL << 20)
#define MAX_CONTAINERS      64

/* ------------------------------------------------------------------ */
/*  Enums                                                               */
/* ------------------------------------------------------------------ */
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

/* ------------------------------------------------------------------ */
/*  Data structures                                                     */
/* ------------------------------------------------------------------ */
typedef struct container_record {
    char              id[CONTAINER_ID_LEN];
    char              rootfs[PATH_MAX];
    pid_t             host_pid;
    time_t            started_at;
    container_state_t state;
    unsigned long     soft_limit_bytes;
    unsigned long     hard_limit_bytes;
    int               exit_code;
    int               exit_signal;
    int               stop_requested; /* set before sending SIGTERM/SIGKILL */
    char              log_path[PATH_MAX];
    struct container_record *next;
} container_record_t;

typedef struct {
    char   container_id[CONTAINER_ID_LEN];
    size_t length;
    char   data[LOG_CHUNK_SIZE];
} log_item_t;

typedef struct {
    log_item_t      items[LOG_BUFFER_CAPACITY];
    size_t          head;
    size_t          tail;
    size_t          count;
    int             shutting_down;
    pthread_mutex_t mutex;
    pthread_cond_t  not_empty;
    pthread_cond_t  not_full;
} bounded_buffer_t;

typedef struct {
    command_kind_t kind;
    char           container_id[CONTAINER_ID_LEN];
    char           rootfs[PATH_MAX];
    char           command[CHILD_COMMAND_LEN];
    unsigned long  soft_limit_bytes;
    unsigned long  hard_limit_bytes;
    int            nice_value;
} control_request_t;

typedef struct {
    int  status;
    char message[CONTROL_MESSAGE_LEN];
} control_response_t;

typedef struct {
    char id[CONTAINER_ID_LEN];
    char rootfs[PATH_MAX];
    char command[CHILD_COMMAND_LEN];
    int  nice_value;
    int  log_write_fd;  /* write-end of the logging pipe */
} child_config_t;

/* per-container producer thread state */
typedef struct {
    int             pipe_read_fd;
    char            container_id[CONTAINER_ID_LEN];
    bounded_buffer_t *buffer;
} producer_arg_t;

typedef struct {
    int              server_fd;
    int              monitor_fd;
    volatile int     should_stop;
    pthread_t        logger_thread;
    bounded_buffer_t log_buffer;
    pthread_mutex_t  metadata_lock;
    container_record_t *containers;
} supervisor_ctx_t;

/* Global supervisor context pointer — used by signal handlers */
static supervisor_ctx_t *g_ctx = NULL;
static volatile sig_atomic_t g_run_client_interrupted = 0;
static volatile sig_atomic_t g_sigchld_pending = 0;

/* ------------------------------------------------------------------ */
/*  Helpers                                                             */
/* ------------------------------------------------------------------ */
static void usage(const char *prog)
{
    fprintf(stderr,
            "Usage:\n"
            "  %s supervisor <base-rootfs>\n"
            "  %s start <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s run   <id> <container-rootfs> <command> [--soft-mib N] [--hard-mib N] [--nice N]\n"
            "  %s ps\n"
            "  %s logs <id>\n"
            "  %s stop <id>\n",
            prog, prog, prog, prog, prog, prog);
}

static int parse_mib_flag(const char *flag, const char *value,
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

static int parse_optional_flags(control_request_t *req, int argc,
                                char *argv[], int start_index)
{
    int i;
    for (i = start_index; i < argc; i += 2) {
        char *end = NULL;
        long  nice_value;
        if (i + 1 >= argc) {
            fprintf(stderr, "Missing value for option: %s\n", argv[i]);
            return -1;
        }
        if (strcmp(argv[i], "--soft-mib") == 0) {
            if (parse_mib_flag("--soft-mib", argv[i + 1],
                               &req->soft_limit_bytes) != 0)
                return -1;
            continue;
        }
        if (strcmp(argv[i], "--hard-mib") == 0) {
            if (parse_mib_flag("--hard-mib", argv[i + 1],
                               &req->hard_limit_bytes) != 0)
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
        fprintf(stderr,
                "Invalid limits: soft limit cannot exceed hard limit\n");
        return -1;
    }
    return 0;
}

static const char *state_to_string(container_state_t state)
{
    switch (state) {
    case CONTAINER_STARTING: return "starting";
    case CONTAINER_RUNNING:  return "running";
    case CONTAINER_STOPPED:  return "stopped";
    case CONTAINER_KILLED:   return "hard_limit_killed";
    case CONTAINER_EXITED:   return "exited";
    default:                 return "unknown";
    }
}

/* Caller must hold metadata_lock */
static int has_running_rootfs_conflict(supervisor_ctx_t *ctx,
                                       const char *container_id,
                                       const char *rootfs)
{
    container_record_t *r;
    for (r = ctx->containers; r; r = r->next) {
        if (strcmp(r->id, container_id) == 0)
            continue;
        if (r->state != CONTAINER_RUNNING && r->state != CONTAINER_STARTING)
            continue;
        if (strcmp(r->rootfs, rootfs) == 0)
            return 1;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Bounded buffer                                                      */
/* ------------------------------------------------------------------ */
static int bounded_buffer_init(bounded_buffer_t *buf)
{
    int rc;
    memset(buf, 0, sizeof(*buf));
    rc = pthread_mutex_init(&buf->mutex, NULL);
    if (rc != 0) return rc;
    rc = pthread_cond_init(&buf->not_empty, NULL);
    if (rc != 0) { pthread_mutex_destroy(&buf->mutex); return rc; }
    rc = pthread_cond_init(&buf->not_full, NULL);
    if (rc != 0) {
        pthread_cond_destroy(&buf->not_empty);
        pthread_mutex_destroy(&buf->mutex);
        return rc;
    }
    return 0;
}

static void bounded_buffer_destroy(bounded_buffer_t *buf)
{
    pthread_cond_destroy(&buf->not_full);
    pthread_cond_destroy(&buf->not_empty);
    pthread_mutex_destroy(&buf->mutex);
}

static void bounded_buffer_begin_shutdown(bounded_buffer_t *buf)
{
    pthread_mutex_lock(&buf->mutex);
    buf->shutting_down = 1;
    pthread_cond_broadcast(&buf->not_empty);
    pthread_cond_broadcast(&buf->not_full);
    pthread_mutex_unlock(&buf->mutex);
}

/*
 * Push one log item onto the buffer.
 * Blocks while full (unless shutdown begins).
 * Returns 0 on success, -1 if shutting down.
 */
int bounded_buffer_push(bounded_buffer_t *buf, const log_item_t *item)
{
    pthread_mutex_lock(&buf->mutex);

    /* Wait while full, but bail out on shutdown */
    while (buf->count == LOG_BUFFER_CAPACITY && !buf->shutting_down)
        pthread_cond_wait(&buf->not_full, &buf->mutex);

    if (buf->shutting_down) {
        pthread_mutex_unlock(&buf->mutex);
        return -1;
    }

    buf->items[buf->tail] = *item;
    buf->tail = (buf->tail + 1) % LOG_BUFFER_CAPACITY;
    buf->count++;

    pthread_cond_signal(&buf->not_empty);
    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

/*
 * Pop one log item from the buffer.
 * Blocks while empty.
 * Returns 0 on success, -1 when shutdown AND buffer is drained.
 */
int bounded_buffer_pop(bounded_buffer_t *buf, log_item_t *item)
{
    pthread_mutex_lock(&buf->mutex);

    /* Wait while empty; on shutdown, drain remaining items first */
    while (buf->count == 0) {
        if (buf->shutting_down) {
            pthread_mutex_unlock(&buf->mutex);
            return -1; /* drained and done */
        }
        pthread_cond_wait(&buf->not_empty, &buf->mutex);
    }

    *item = buf->items[buf->head];
    buf->head = (buf->head + 1) % LOG_BUFFER_CAPACITY;
    buf->count--;

    pthread_cond_signal(&buf->not_full);
    pthread_mutex_unlock(&buf->mutex);
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Logging consumer thread                                             */
/* ------------------------------------------------------------------ */
/*
 * Runs in the supervisor. Pops log items from the bounded buffer and
 * appends them to per-container log files in LOG_DIR/.
 */
void *logging_thread(void *arg)
{
    bounded_buffer_t *buf = (bounded_buffer_t *)arg;
    log_item_t item;

    while (bounded_buffer_pop(buf, &item) == 0) {
        char path[PATH_MAX];
        int  fd;

        snprintf(path, sizeof(path), "%s/%s.log", LOG_DIR,
                 item.container_id);

        fd = open(path, O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            perror("logging_thread: open log file");
            continue;
        }
        if (write(fd, item.data, item.length) < 0)
            perror("logging_thread: write");
        close(fd);
    }

    fprintf(stderr, "[supervisor] logging thread exiting, buffer drained.\n");
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Per-container producer thread                                       */
/* ------------------------------------------------------------------ */
/*
 * Reads from the container's pipe read-end and pushes chunks into the
 * bounded buffer. Exits when EOF is reached (container exited).
 */
static void *producer_thread(void *arg)
{
    producer_arg_t *pa  = (producer_arg_t *)arg;
    log_item_t      item;
    ssize_t         n;

    memset(&item, 0, sizeof(item));
    strncpy(item.container_id, pa->container_id,
            sizeof(item.container_id) - 1);

    while ((n = read(pa->pipe_read_fd, item.data, LOG_CHUNK_SIZE)) > 0) {
        item.length = (size_t)n;
        /* push; ignore return — on shutdown we just stop */
        bounded_buffer_push(pa->buffer, &item);
        memset(item.data, 0, sizeof(item.data));
    }

    close(pa->pipe_read_fd);
    free(pa);
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  Container child entrypoint (runs inside clone())                    */
/* ------------------------------------------------------------------ */
int child_fn(void *arg)
{
    child_config_t *cfg = (child_config_t *)arg;

    /* Redirect stdout and stderr to the logging pipe */
    if (cfg->log_write_fd >= 0) {
        dup2(cfg->log_write_fd, STDOUT_FILENO);
        dup2(cfg->log_write_fd, STDERR_FILENO);
        close(cfg->log_write_fd);
    }

    /* Set nice value if requested */
    if (cfg->nice_value != 0)
        nice(cfg->nice_value);

    /* Set hostname to container ID (UTS namespace) */
    if (sethostname(cfg->id, strlen(cfg->id)) != 0)
        perror("sethostname");

    /* chroot into the container's rootfs */
    if (chroot(cfg->rootfs) != 0) {
        perror("chroot");
        return 1;
    }
    if (chdir("/") != 0) {
        perror("chdir /");
        return 1;
    }

    /* Mount /proc so ps, top, etc. work inside the container */
    if (mount("proc", "/proc", "proc",
              MS_NOSUID | MS_NOEXEC | MS_NODEV, NULL) != 0) {
        /* Non-fatal: /proc may already be mounted or rootfs may lack it */
        perror("mount /proc (non-fatal)");
    }

    /* Execute the requested command. */
    if (strchr(cfg->command, ' ') || strchr(cfg->command, '\t')) {
        execl("/bin/sh", "sh", "-c", cfg->command, (char *)NULL);
        perror("execl /bin/sh -c");
        return 1;
    }

    {
        char *const argv[] = { cfg->command, NULL };
        execv(cfg->command, argv);
    }

    /* If execv returns, something went wrong */
    perror("execv");
    return 1;
}

/* ------------------------------------------------------------------ */
/*  Monitor ioctl helpers                                               */
/* ------------------------------------------------------------------ */
int register_with_monitor(int monitor_fd, const char *container_id,
                          pid_t host_pid, unsigned long soft_limit_bytes,
                          unsigned long hard_limit_bytes)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid               = host_pid;
    req.soft_limit_bytes  = soft_limit_bytes;
    req.hard_limit_bytes  = hard_limit_bytes;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;
    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id,
                            pid_t host_pid)
{
    struct monitor_request req;
    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);
    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  Container metadata helpers                                          */
/* ------------------------------------------------------------------ */

/* Caller must hold ctx->metadata_lock */
static container_record_t *find_container(supervisor_ctx_t *ctx,
                                          const char *id)
{
    container_record_t *r;
    for (r = ctx->containers; r; r = r->next)
        if (strcmp(r->id, id) == 0)
            return r;
    return NULL;
}

/* ------------------------------------------------------------------ */
/*  SIGCHLD handler — reaps exited children                            */
/* ------------------------------------------------------------------ */
static void sigchld_handler(int sig)
{
    (void)sig;
    g_sigchld_pending = 1;
}

static void reap_exited_children(supervisor_ctx_t *ctx)
{
    int   status;
    pid_t pid;

    while ((pid = waitpid(-1, &status, WNOHANG)) > 0) {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r;
        for (r = ctx->containers; r; r = r->next) {
            if (r->host_pid != pid)
                continue;

            if (WIFEXITED(status)) {
                r->exit_code = WEXITSTATUS(status);
                r->exit_signal = 0;
                r->state = CONTAINER_EXITED;
            } else if (WIFSIGNALED(status)) {
                r->exit_signal = WTERMSIG(status);
                r->exit_code = 0;
                if (r->stop_requested)
                    r->state = CONTAINER_STOPPED;
                else if (r->exit_signal == SIGKILL)
                    r->state = CONTAINER_KILLED;
                else
                    r->state = CONTAINER_EXITED;
            }

            if (ctx->monitor_fd >= 0)
                unregister_from_monitor(ctx->monitor_fd, r->id, pid);

            fprintf(stderr,
                    "[supervisor] container '%s' (pid %d) exited: "
                    "state=%s exit_code=%d exit_signal=%d\n",
                    r->id, pid, state_to_string(r->state),
                    r->exit_code, r->exit_signal);
            break;
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
    }
}

/* ------------------------------------------------------------------ */
/*  SIGINT / SIGTERM — orderly supervisor shutdown                      */
/* ------------------------------------------------------------------ */
static void shutdown_handler(int sig)
{
    (void)sig;
    if (g_ctx)
        g_ctx->should_stop = 1;
}

/* ------------------------------------------------------------------ */
/*  Launch one container                                                */
/* ------------------------------------------------------------------ */
/*
 * Creates a pipe for logging, clones a child with new namespaces,
 * registers it with the kernel monitor, starts a producer thread, and
 * adds the container record to the supervisor's metadata list.
 *
 * Caller must hold ctx->metadata_lock around the metadata list insert
 * AFTER clone() returns the PID.
 *
 * Returns the new container_record_t*, or NULL on error.
 */
static container_record_t *launch_container(supervisor_ctx_t *ctx,
                                            const control_request_t *req)
{
    int pipefd[2];
    if (pipe(pipefd) != 0) {
        perror("pipe");
        return NULL;
    }

    /* Build child config on heap so it outlives this stack frame */
    child_config_t *cfg = calloc(1, sizeof(*cfg));
    if (!cfg) { close(pipefd[0]); close(pipefd[1]); return NULL; }

    strncpy(cfg->id,      req->container_id, sizeof(cfg->id) - 1);
    strncpy(cfg->rootfs,  req->rootfs,        sizeof(cfg->rootfs) - 1);
    strncpy(cfg->command, req->command,        sizeof(cfg->command) - 1);
    cfg->nice_value    = req->nice_value;
    cfg->log_write_fd  = pipefd[1];

    /* Allocate clone stack */
    char *stack = malloc(STACK_SIZE);
    if (!stack) {
        free(cfg);
        close(pipefd[0]); close(pipefd[1]);
        return NULL;
    }
    char *stack_top = stack + STACK_SIZE;

    /* Ensure log directory exists */
    mkdir(LOG_DIR, 0755);

    /* Clone child with isolated namespaces */
    int clone_flags = CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD;
    pid_t child_pid = clone(child_fn, stack_top, clone_flags, cfg);

    /* Parent closes the write end of the pipe */
    close(pipefd[1]);

    if (child_pid < 0) {
        perror("clone");
        free(stack);
        free(cfg);
        close(pipefd[0]);
        return NULL;
    }

    /* stack is leaked intentionally — the child uses it until execv */
    /* (a real runtime would track it for freeing after waitpid)      */

    /* Register with kernel monitor */
    if (ctx->monitor_fd >= 0) {
        if (register_with_monitor(ctx->monitor_fd, req->container_id,
                                  child_pid,
                                  req->soft_limit_bytes,
                                  req->hard_limit_bytes) != 0)
            perror("register_with_monitor (non-fatal)");
    }

    /* Build metadata record */
    container_record_t *rec = calloc(1, sizeof(*rec));
    if (!rec) {
        /* Kill the child we just launched */
        kill(child_pid, SIGKILL);
        close(pipefd[0]);
        return NULL;
    }
    strncpy(rec->id, req->container_id, sizeof(rec->id) - 1);
    strncpy(rec->rootfs, req->rootfs, sizeof(rec->rootfs) - 1);
    rec->host_pid          = child_pid;
    rec->started_at        = time(NULL);
    rec->state             = CONTAINER_RUNNING;
    rec->soft_limit_bytes  = req->soft_limit_bytes;
    rec->hard_limit_bytes  = req->hard_limit_bytes;
    snprintf(rec->log_path, sizeof(rec->log_path),
             "%s/%s.log", LOG_DIR, req->container_id);

    /* Insert at head of list (under caller's metadata_lock) */
    pthread_mutex_lock(&ctx->metadata_lock);
    rec->next         = ctx->containers;
    ctx->containers   = rec;
    pthread_mutex_unlock(&ctx->metadata_lock);

    /* Spawn a producer thread to read from the pipe */
    producer_arg_t *pa = calloc(1, sizeof(*pa));
    if (pa) {
        pa->pipe_read_fd = pipefd[0];
        strncpy(pa->container_id, req->container_id,
                sizeof(pa->container_id) - 1);
        pa->buffer = &ctx->log_buffer;
        pthread_t tid;
        if (pthread_create(&tid, NULL, producer_thread, pa) == 0)
            pthread_detach(tid);   /* we don't join producers explicitly */
        else { free(pa); close(pipefd[0]); }
    } else {
        close(pipefd[0]);
    }

    fprintf(stderr, "[supervisor] started container '%s' pid=%d\n",
            req->container_id, child_pid);
    return rec;
}

/* ------------------------------------------------------------------ */
/*  Handle one control request from a CLI client                        */
/* ------------------------------------------------------------------ */
static void handle_request(supervisor_ctx_t *ctx, int client_fd)
{
    control_request_t  req;
    control_response_t resp;

    memset(&resp, 0, sizeof(resp));

    ssize_t n = read(client_fd, &req, sizeof(req));
    if (n != (ssize_t)sizeof(req)) {
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "bad request size");
        write(client_fd, &resp, sizeof(resp));
        return;
    }

    switch (req.kind) {

    /* ---- START ---- */
    case CMD_START: {
        /* Check duplicate ID */
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *existing = find_container(ctx, req.container_id);
        int rootfs_conflict = has_running_rootfs_conflict(ctx,
                                                          req.container_id,
                                                          req.rootfs);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (existing && (existing->state == CONTAINER_RUNNING ||
                         existing->state == CONTAINER_STARTING)) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "container '%s' already running", req.container_id);
            break;
        }
        if (rootfs_conflict) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "rootfs '%s' already used by a running container",
                     req.rootfs);
            break;
        }

        container_record_t *rec = launch_container(ctx, &req);
        if (!rec) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "failed to launch container '%s'", req.container_id);
        } else {
            resp.status = 0;
            snprintf(resp.message, sizeof(resp.message),
                     "started container '%s' pid=%d",
                     req.container_id, rec->host_pid);
        }
        break;
    }

    /* ---- RUN (same as START — client blocks waiting for exit code) ---- */
    case CMD_RUN: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *existing = find_container(ctx, req.container_id);
        int rootfs_conflict = has_running_rootfs_conflict(ctx,
                                                          req.container_id,
                                                          req.rootfs);
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (existing && (existing->state == CONTAINER_RUNNING ||
                         existing->state == CONTAINER_STARTING)) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "container '%s' already running", req.container_id);
            break;
        }
        if (rootfs_conflict) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "rootfs '%s' already used by a running container",
                     req.rootfs);
            break;
        }

        container_record_t *rec = launch_container(ctx, &req);
        if (!rec) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "failed to launch container '%s'", req.container_id);
            break;
        }

        /*
         * Wait until SIGCHLD handling updates final state/exit info.
         * This avoids a race where direct waitpid() in this path can consume
         * the child and leave stale exit_code/exit_signal metadata.
         */
        while (1) {
            reap_exited_children(ctx);

            int done;
            pthread_mutex_lock(&ctx->metadata_lock);
            done = (rec->state != CONTAINER_RUNNING &&
                    rec->state != CONTAINER_STARTING);
            pthread_mutex_unlock(&ctx->metadata_lock);
            if (done)
                break;
            usleep(100000); /* 100 ms */
        }

        /* SIGCHLD handler may have already updated state; just read it */
        pthread_mutex_lock(&ctx->metadata_lock);
        int exit_code   = rec->exit_code;
        int exit_signal = rec->exit_signal;
        pthread_mutex_unlock(&ctx->metadata_lock);

        if (exit_signal)
            resp.status = 128 + exit_signal;
        else
            resp.status = exit_code;
        snprintf(resp.message, sizeof(resp.message),
                 "container '%s' exited status=%d",
                 req.container_id, resp.status);
        break;
    }

    /* ---- PS ---- */
    case CMD_PS: {
        char buf[4096];
        int  off = 0;
        off += snprintf(buf + off, sizeof(buf) - off,
                        "%-16s %-8s %-10s %-20s %-10s %-10s\n",
                        "ID", "PID", "STATE",
                        "STARTED", "SOFT(MiB)", "HARD(MiB)");
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *r;
        for (r = ctx->containers; r && off < (int)sizeof(buf) - 128;
             r = r->next) {
            char timebuf[24];
            struct tm *tm = localtime(&r->started_at);
            strftime(timebuf, sizeof(timebuf), "%H:%M:%S", tm);
            off += snprintf(buf + off, sizeof(buf) - off,
                            "%-16s %-8d %-10s %-20s %-10lu %-10lu\n",
                            r->id, r->host_pid,
                            state_to_string(r->state), timebuf,
                            r->soft_limit_bytes >> 20,
                            r->hard_limit_bytes >> 20);
        }
        pthread_mutex_unlock(&ctx->metadata_lock);
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message), "container table:");
        write(client_fd, &resp, sizeof(resp));
        write(client_fd, buf, (size_t)off);
        return;
        break;
    }

    /* ---- LOGS ---- */
    case CMD_LOGS: {
        char log_path[PATH_MAX];
        snprintf(log_path, sizeof(log_path), "%s/%s.log",
                 LOG_DIR, req.container_id);

        int lfd = open(log_path, O_RDONLY);
        if (lfd < 0) {
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "no log for container '%s'", req.container_id);
            write(client_fd, &resp, sizeof(resp));
            /* send log file content as extra data */
            return;
        }

        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message),
                 "log for '%s':", req.container_id);
        write(client_fd, &resp, sizeof(resp));

        /* Stream log file content directly to the client */
        char chunk[4096];
        ssize_t rn;
        while ((rn = read(lfd, chunk, sizeof(chunk))) > 0)
            write(client_fd, chunk, (size_t)rn);
        close(lfd);
        return;  /* already sent response */
    }

    /* ---- STOP ---- */
    case CMD_STOP: {
        pthread_mutex_lock(&ctx->metadata_lock);
        container_record_t *rec = find_container(ctx, req.container_id);
        if (!rec || rec->state != CONTAINER_RUNNING) {
            pthread_mutex_unlock(&ctx->metadata_lock);
            resp.status = -1;
            snprintf(resp.message, sizeof(resp.message),
                     "container '%s' not running", req.container_id);
            break;
        }
        rec->stop_requested = 1;
        pid_t pid = rec->host_pid;
        pthread_mutex_unlock(&ctx->metadata_lock);

        /* Graceful: SIGTERM, then SIGKILL after 3 s */
        kill(pid, SIGTERM);
        struct timespec deadline = {0};
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += 3;

        while (1) {
            reap_exited_children(ctx);

            struct timespec now = {0};
            clock_gettime(CLOCK_MONOTONIC, &now);
            if (now.tv_sec > deadline.tv_sec ||
                (now.tv_sec == deadline.tv_sec &&
                 now.tv_nsec >= deadline.tv_nsec))
                break;

            pthread_mutex_lock(&ctx->metadata_lock);
            container_state_t st = rec->state;
            pthread_mutex_unlock(&ctx->metadata_lock);
            if (st != CONTAINER_RUNNING) goto stop_done;

            usleep(100000); /* 100 ms */
        }
        /* Still running — force kill */
        kill(pid, SIGKILL);
    stop_done:
        resp.status = 0;
        snprintf(resp.message, sizeof(resp.message),
                 "stopped container '%s'", req.container_id);
        break;
    }

    default:
        resp.status = -1;
        snprintf(resp.message, sizeof(resp.message), "unknown command");
        break;
    }

    write(client_fd, &resp, sizeof(resp));
}

/* ------------------------------------------------------------------ */
/*  Supervisor event loop                                               */
/* ------------------------------------------------------------------ */
static int run_supervisor(const char *rootfs)
{
    (void)rootfs; /* base-rootfs argument kept for CLI compatibility */

    supervisor_ctx_t ctx;
    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd  = -1;
    ctx.monitor_fd = -1;
    g_ctx = &ctx;

    /* --- Init metadata lock --- */
    int rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) { errno = rc; perror("pthread_mutex_init"); return 1; }

    /* --- Init bounded buffer --- */
    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc; perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    /* --- Ensure log directory exists --- */
    mkdir(LOG_DIR, 0755);

    /* --- Open kernel monitor device (optional — continue if absent) --- */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0)
        fprintf(stderr,
                "[supervisor] /dev/container_monitor not available "
                "(kernel module not loaded?), continuing without it.\n");

    /* --- Create UNIX domain socket --- */
    unlink(CONTROL_PATH); /* remove stale socket */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) { perror("socket"); goto cleanup; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); goto cleanup;
    }
    if (listen(ctx.server_fd, 8) < 0) {
        perror("listen"); goto cleanup;
    }

    /* --- Install signal handlers --- */
    struct sigaction sa_chld, sa_term;
    memset(&sa_chld, 0, sizeof(sa_chld));
    sa_chld.sa_handler = sigchld_handler;
    sa_chld.sa_flags   = SA_RESTART | SA_NOCLDSTOP;
    sigaction(SIGCHLD, &sa_chld, NULL);

    memset(&sa_term, 0, sizeof(sa_term));
    sa_term.sa_handler = shutdown_handler;
    sigaction(SIGINT,  &sa_term, NULL);
    sigaction(SIGTERM, &sa_term, NULL);

    /* --- Start logging consumer thread --- */
    rc = pthread_create(&ctx.logger_thread, NULL,
                        logging_thread, &ctx.log_buffer);
    if (rc != 0) {
        errno = rc; perror("pthread_create logger");
        goto cleanup;
    }

    fprintf(stderr, "[supervisor] ready. socket=%s\n", CONTROL_PATH);

    /* ---- Main accept loop ---- */
    while (!ctx.should_stop) {
        if (g_sigchld_pending) {
            g_sigchld_pending = 0;
            reap_exited_children(&ctx);
        }

        /* Use select() with a short timeout so we can check should_stop */
        fd_set rfds;
        FD_ZERO(&rfds);
        FD_SET(ctx.server_fd, &rfds);
        struct timeval tv = { .tv_sec = 1, .tv_usec = 0 };

        int sel = select(ctx.server_fd + 1, &rfds, NULL, NULL, &tv);
        if (sel < 0) {
            if (errno == EINTR) continue; /* signal interrupted */
            perror("select");
            break;
        }
        if (sel == 0) continue; /* timeout — loop and check should_stop */

        int client_fd = accept(ctx.server_fd, NULL, NULL);
        if (client_fd < 0) {
            if (errno == EINTR) continue;
            perror("accept");
            continue;
        }
        handle_request(&ctx, client_fd);
        close(client_fd);

        if (g_sigchld_pending) {
            g_sigchld_pending = 0;
            reap_exited_children(&ctx);
        }
    }

    fprintf(stderr, "[supervisor] shutting down...\n");

    /* Stop all running containers */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *r;
    for (r = ctx.containers; r; r = r->next) {
        if (r->state == CONTAINER_RUNNING) {
            r->stop_requested = 1;
            kill(r->host_pid, SIGTERM);
        }
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Brief wait for containers to exit */
    usleep(500000);
    pthread_mutex_lock(&ctx.metadata_lock);
    for (r = ctx.containers; r; r = r->next) {
        if (r->state == CONTAINER_RUNNING)
            kill(r->host_pid, SIGKILL);
    }
    pthread_mutex_unlock(&ctx.metadata_lock);

    /* Drain any remaining children */
    reap_exited_children(&ctx);

cleanup:
    /* Signal logger thread to stop and join it */
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    if (ctx.logger_thread)
        pthread_join(ctx.logger_thread, NULL);

    bounded_buffer_destroy(&ctx.log_buffer);

    /* Free container metadata list */
    pthread_mutex_lock(&ctx.metadata_lock);
    container_record_t *cur = ctx.containers;
    while (cur) {
        container_record_t *nxt = cur->next;
        free(cur);
        cur = nxt;
    }
    ctx.containers = NULL;
    pthread_mutex_unlock(&ctx.metadata_lock);
    pthread_mutex_destroy(&ctx.metadata_lock);

    if (ctx.server_fd >= 0) { close(ctx.server_fd); unlink(CONTROL_PATH); }
    if (ctx.monitor_fd >= 0) close(ctx.monitor_fd);

    fprintf(stderr, "[supervisor] clean exit.\n");
    g_ctx = NULL;
    return 0;
}

/* ------------------------------------------------------------------ */
/*  CLI client — sends a request to the running supervisor              */
/* ------------------------------------------------------------------ */
static int send_control_request(const control_request_t *req)
{
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { perror("socket"); return 1; }

    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect (is the supervisor running?)");
        close(fd);
        return 1;
    }

    if (write(fd, req, sizeof(*req)) != (ssize_t)sizeof(*req)) {
        perror("write request");
        close(fd);
        return 1;
    }

    control_response_t resp;
    if (req->kind == CMD_RUN) {
        int stop_forwarded = 0;
        while (1) {
            fd_set rfds;
            struct timeval tv;
            FD_ZERO(&rfds);
            FD_SET(fd, &rfds);
            tv.tv_sec = 0;
            tv.tv_usec = 200000; /* 200 ms */

            int sel = select(fd + 1, &rfds, NULL, NULL, &tv);
            if (sel < 0) {
                if (errno == EINTR)
                    continue;
                perror("select response");
                close(fd);
                return 1;
            }

            if (sel > 0 && FD_ISSET(fd, &rfds))
                break;

            if (g_run_client_interrupted && !stop_forwarded) {
                control_request_t stop_req;
                int stop_fd;
                struct sockaddr_un stop_addr;

                memset(&stop_req, 0, sizeof(stop_req));
                stop_req.kind = CMD_STOP;
                strncpy(stop_req.container_id, req->container_id,
                        sizeof(stop_req.container_id) - 1);

                stop_fd = socket(AF_UNIX, SOCK_STREAM, 0);
                if (stop_fd >= 0) {
                    memset(&stop_addr, 0, sizeof(stop_addr));
                    stop_addr.sun_family = AF_UNIX;
                    strncpy(stop_addr.sun_path, CONTROL_PATH,
                            sizeof(stop_addr.sun_path) - 1);

                    if (connect(stop_fd, (struct sockaddr *)&stop_addr,
                                sizeof(stop_addr)) == 0) {
                        if (write(stop_fd, &stop_req, sizeof(stop_req)) ==
                            (ssize_t)sizeof(stop_req)) {
                            control_response_t stop_resp;
                            (void)read(stop_fd, &stop_resp,
                                       sizeof(stop_resp));
                        }
                    }
                    close(stop_fd);
                }
                stop_forwarded = 1;
            }
        }
    }

    if (read(fd, &resp, sizeof(resp)) != (ssize_t)sizeof(resp)) {
        perror("read response");
        close(fd);
        return 1;
    }
    printf("%s\n", resp.message);

    /* For CMD_LOGS the supervisor streams log content after the header */
    if ((req->kind == CMD_LOGS || req->kind == CMD_PS) && resp.status == 0) {
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0)
            fwrite(buf, 1, (size_t)n, stdout);
    }

    close(fd);
    if (req->kind == CMD_RUN)
        return (resp.status >= 0 && resp.status <= 255) ? resp.status : 1;
    return (resp.status == 0) ? 0 : 1;
}

static void run_client_signal_handler(int sig)
{
    (void)sig;
    g_run_client_interrupted = 1;
}

/* ------------------------------------------------------------------ */
/*  CLI command handlers                                                */
/* ------------------------------------------------------------------ */
static int cmd_start(int argc, char *argv[])
{
    control_request_t req;
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s start <id> <container-rootfs> <command> "
                "[--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_START;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,      argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;
    return send_control_request(&req);
}

static int cmd_run(int argc, char *argv[])
{
    control_request_t req;
    struct sigaction sa, old_int, old_term;
    int rc;
    if (argc < 5) {
        fprintf(stderr,
                "Usage: %s run <id> <container-rootfs> <command> "
                "[--soft-mib N] [--hard-mib N] [--nice N]\n", argv[0]);
        return 1;
    }
    memset(&req, 0, sizeof(req));
    req.kind = CMD_RUN;
    strncpy(req.container_id, argv[2], sizeof(req.container_id) - 1);
    strncpy(req.rootfs,       argv[3], sizeof(req.rootfs) - 1);
    strncpy(req.command,      argv[4], sizeof(req.command) - 1);
    req.soft_limit_bytes = DEFAULT_SOFT_LIMIT;
    req.hard_limit_bytes = DEFAULT_HARD_LIMIT;
    if (parse_optional_flags(&req, argc, argv, 5) != 0) return 1;

    g_run_client_interrupted = 0;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = run_client_signal_handler;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT, &sa, &old_int);
    sigaction(SIGTERM, &sa, &old_term);

    rc = send_control_request(&req);

    sigaction(SIGINT, &old_int, NULL);
    sigaction(SIGTERM, &old_term, NULL);
    return rc;
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

/* ------------------------------------------------------------------ */
/*  main                                                                */
/* ------------------------------------------------------------------ */
int main(int argc, char *argv[])
{
    if (argc < 2) { usage(argv[0]); return 1; }

    if (strcmp(argv[1], "supervisor") == 0) {
        if (argc < 3) {
            fprintf(stderr, "Usage: %s supervisor <base-rootfs>\n", argv[0]);
            return 1;
        }
        return run_supervisor(argv[2]);
    }
    if (strcmp(argv[1], "start") == 0) return cmd_start(argc, argv);
    if (strcmp(argv[1], "run")   == 0) return cmd_run(argc, argv);
    if (strcmp(argv[1], "ps")    == 0) return cmd_ps();
    if (strcmp(argv[1], "logs")  == 0) return cmd_logs(argc, argv);
    if (strcmp(argv[1], "stop")  == 0) return cmd_stop(argc, argv);

    usage(argv[0]);
    return 1;
}