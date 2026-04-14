/*
 * engine.c - Supervised Multi-Container Runtime (User Space)
 *
 * Intentionally partial starter:
 *   - command-line shape is defined
 *   - key runtime data structures are defined
 *   - bounded-buffer skeleton is defined
 *   - supervisor / client split is outlined
 *
 * Students are expected to design:
 *   - the control-plane IPC implementation
 *   - container lifecycle and metadata synchronization
 *   - clone + namespace setup for each container
 *   - producer/consumer behavior for log buffering
 *   - signal handling and graceful shutdown
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
#include <sys/resource.h>
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
    container_record_t *containers;
} supervisor_ctx_t;

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
 * TODO:
 * Implement producer-side insertion into the bounded buffer.
 *
 * Requirements:
 *   - block or fail according to your chosen policy when the buffer is full
 *   - wake consumers correctly
 *   - stop cleanly if shutdown begins
 */
int bounded_buffer_push(bounded_buffer_t *buffer, const log_item_t *item)
{
    int rc = 0;

    pthread_mutex_lock(&buffer->mutex);

    /* Wait while the buffer is full and not shutting down */
    while (buffer->count >= LOG_BUFFER_CAPACITY && !buffer->shutting_down) {
        rc = pthread_cond_wait(&buffer->not_full, &buffer->mutex);
        if (rc != 0) {
            pthread_mutex_unlock(&buffer->mutex);
            return -1;
        }
    }

    if (buffer->shutting_down) {
        pthread_mutex_unlock(&buffer->mutex);
        return -1;
    }

    /* Insert the item */
    buffer->items[buffer->tail] = *item;
    buffer->tail = (buffer->tail + 1) % LOG_BUFFER_CAPACITY;
    buffer->count++;

    /* Wake up consumers */
    pthread_cond_signal(&buffer->not_empty);

    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * TODO:
 * Implement consumer-side removal from the bounded buffer.
 *
 * Requirements:
 *   - wait correctly while the buffer is empty
 *   - return a useful status when shutdown is in progress
 *   - avoid races with producers and shutdown
 */
int bounded_buffer_pop(bounded_buffer_t *buffer, log_item_t *item)
{
    int rc = 0;

    pthread_mutex_lock(&buffer->mutex);

    /* Wait while the buffer is empty */
    while (buffer->count == 0) {
        if (buffer->shutting_down) {
            /* Shutdown signal, consumer should exit */
            pthread_mutex_unlock(&buffer->mutex);
            return 1;
        }
        rc = pthread_cond_wait(&buffer->not_empty, &buffer->mutex);
        if (rc != 0) {
            pthread_mutex_unlock(&buffer->mutex);
            return -1;
        }
    }

    /* Check for shutdown after waiting */
    if (buffer->shutting_down && buffer->count == 0) {
        pthread_mutex_unlock(&buffer->mutex);
        return 1;
    }

    /* Remove the item from the head */
    *item = buffer->items[buffer->head];
    buffer->head = (buffer->head + 1) % LOG_BUFFER_CAPACITY;
    buffer->count--;

    /* Wake up producers */
    pthread_cond_signal(&buffer->not_full);

    pthread_mutex_unlock(&buffer->mutex);
    return 0;
}

/*
 * Thread function to read from a container's output pipes and push to the buffer.
 */
typedef struct {
    supervisor_ctx_t *ctx;
    int pipe_fd;
    char container_id[CONTAINER_ID_LEN];
} pipe_reader_arg_t;

void *pipe_reader_thread(void *arg)
{
    pipe_reader_arg_t *reader_arg = (pipe_reader_arg_t *)arg;
    supervisor_ctx_t *ctx = reader_arg->ctx;
    int pipe_fd = reader_arg->pipe_fd;
    char container_id_copy[CONTAINER_ID_LEN];
    log_item_t item;
    ssize_t nread;

    strncpy(container_id_copy, reader_arg->container_id, sizeof(container_id_copy) - 1);
    free(reader_arg);

    while (1) {
        memset(&item, 0, sizeof(item));
        strncpy(item.container_id, container_id_copy, sizeof(item.container_id) - 1);

        nread = read(pipe_fd, item.data, sizeof(item.data) - 1);
        if (nread <= 0)
            break;

        item.length = (size_t)nread;
        bounded_buffer_push(&ctx->log_buffer, &item);
    }

    close(pipe_fd);
    free(arg);
    return NULL;
}

/*
 * TODO:
 * Implement the logging consumer thread.
 *
 * Suggested responsibilities:
 *   - remove log chunks from the bounded buffer
 *   - route each chunk to the correct per-container log file
 *   - exit cleanly when shutdown begins and pending work is drained
 */
void *logging_thread(void *arg)
{
    supervisor_ctx_t *ctx = (supervisor_ctx_t *)arg;
    log_item_t item;
    FILE *log_file;
    int rc;
    char log_path[PATH_MAX];

    while (1) {
        rc = bounded_buffer_pop(&ctx->log_buffer, &item);
        if (rc > 0) {
            /* Shutdown signal */
            break;
        }
        if (rc < 0) {
            /* Error */
            continue;
        }

        /* Get the log file path for this container */
        snprintf(log_path, sizeof(log_path), "%s/%s.log", LOG_DIR, item.container_id);

        /* Open the log file for append */
        log_file = fopen(log_path, "a");
        if (!log_file) {
            fprintf(stderr, "Failed to open log file %s\n", log_path);
            continue;
        }

        /* Write the log data */
        if (fwrite(item.data, 1, item.length, log_file) != item.length) {
            fprintf(stderr, "Failed to write to log file %s\n", log_path);
        }
        fflush(log_file);
        fclose(log_file);
    }

    return NULL;
}

/*
 * TODO:
 * Implement the clone child entrypoint.
 *
 * Required outcomes:
 *   - isolated PID / UTS / mount context
 *   - chroot or pivot_root into rootfs
 *   - working /proc inside container
 *   - stdout / stderr redirected to the supervisor logging path
 *   - configured command executed inside the container
 */
int child_fn(void *arg)
{
    child_config_t *config = (child_config_t *)arg;
    struct sched_param sp;

    if (!config)
        return 1;

    /* Set nice value if specified */
    if (config->nice_value != 0) {
        if (setpriority(PRIO_PROCESS, 0, config->nice_value) != 0) {
            perror("setpriority");
        }
    }

    /* Chroot into the container rootfs */
    if (chdir(config->rootfs) != 0) {
        perror("chdir to rootfs");
        return 1;
    }

    if (chroot(".") != 0) {
        perror("chroot");
        return 1;
    }

    if (chdir("/") != 0) {
        perror("chdir to root");
        return 1;
    }

    /* Mount /proc so container can see its own processes */
    if (mkdir("/proc", 0755) != 0 && errno != EEXIST) {
        perror("mkdir /proc");
    }

    if (mount("proc", "/proc", "proc", 0, NULL) != 0) {
        perror("mount /proc");
        return 1;
    }

    /* Redirect stdout and stderr to the logging pipe */
    if (config->log_write_fd >= 0) {
        dup2(config->log_write_fd, STDOUT_FILENO);
        dup2(config->log_write_fd, STDERR_FILENO);
        if (config->log_write_fd > 2) {
            close(config->log_write_fd);
        }
    }

    /* Execute the container command */
    execl("/bin/sh", "sh", "-c", config->command, (char *)NULL);

    /* If execl fails */
    perror("execl");
    return 1;
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
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_REGISTER, &req) < 0)
        return -1;

    return 0;
}

int unregister_from_monitor(int monitor_fd, const char *container_id, pid_t host_pid)
{
    struct monitor_request req;

    memset(&req, 0, sizeof(req));
    req.pid = host_pid;
    strncpy(req.container_id, container_id, sizeof(req.container_id) - 1);

    if (ioctl(monitor_fd, MONITOR_UNREGISTER, &req) < 0)
        return -1;

    return 0;
}

/* Global for signal handling */
static supervisor_ctx_t *g_supervisor_ctx = NULL;

static void handle_sigchld(int sig)
{
    (void)sig;
    /* Just interrupt the event loop; actual reaping happens in the main loop */
}

static void handle_sigterm(int sig)
{
    (void)sig;
    if (g_supervisor_ctx)
        g_supervisor_ctx->should_stop = 1;
}

/*
 * TODO:
 * Implement the long-running supervisor process.
 *
 * Suggested responsibilities:
 *   - create and bind the control-plane IPC endpoint
 *   - initialize shared metadata and the bounded buffer
 *   - start the logging thread
 *   - accept control requests and update container state
 *   - reap children and respond to signals
 */
static int run_supervisor(const char *rootfs)
{
    supervisor_ctx_t ctx;
    struct sockaddr_un addr;
    int rc, conn_fd;
    pthread_attr_t attr;
    char buf[CONTROL_MESSAGE_LEN];
    struct sigaction sa;
    control_request_t req;
    control_response_t resp;

    memset(&ctx, 0, sizeof(ctx));
    ctx.server_fd = -1;
    ctx.monitor_fd = -1;
    ctx.containers = NULL;
    g_supervisor_ctx = &ctx;

    /* Initialize metadata lock and bounded buffer */
    rc = pthread_mutex_init(&ctx.metadata_lock, NULL);
    if (rc != 0) {
        errno = rc;
        perror("pthread_mutex_init");
        return 1;
    }

    rc = bounded_buffer_init(&ctx.log_buffer);
    if (rc != 0) {
        errno = rc;
        perror("bounded_buffer_init");
        pthread_mutex_destroy(&ctx.metadata_lock);
        return 1;
    }

    /* Create logs directory */
    mkdir(LOG_DIR, 0755);

    /* Open /dev/container_monitor */
    ctx.monitor_fd = open("/dev/container_monitor", O_RDWR);
    if (ctx.monitor_fd < 0) {
        fprintf(stderr, "Warning: Could not open /dev/container_monitor\n");
        /* Continue anyway, monitor may not be loaded */
    }

    /* Create control socket */
    ctx.server_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (ctx.server_fd < 0) {
        perror("socket");
        goto cleanup;
    }

    /* Remove old socket file if it exists */
    unlink(CONTROL_PATH);

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (bind(ctx.server_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind");
        goto cleanup;
    }

    if (listen(ctx.server_fd, 5) < 0) {
        perror("listen");
        goto cleanup;
    }

    /* Install signal handlers */
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_sigchld;
    sigaction(SIGCHLD, &sa, NULL);

    sa.sa_handler = handle_sigterm;
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    /* Start logging thread */
    rc = pthread_create(&ctx.logger_thread, NULL, logging_thread, &ctx);
    if (rc != 0) {
        errno = rc;
        perror("pthread_create logger_thread");
        goto cleanup;
    }

    fprintf(stderr, "[supervisor] Started with rootfs=%s, listening on %s\n", rootfs, CONTROL_PATH);

    /* Event loop */
    while (!ctx.should_stop) {
        fd_set readfds;
        int max_fd;
        struct timeval tv;
        int nready;

        FD_ZERO(&readfds);
        FD_SET(ctx.server_fd, &readfds);
        max_fd = ctx.server_fd;

        tv.tv_sec = 1;
        tv.tv_usec = 0;

        nready = select(max_fd + 1, &readfds, NULL, NULL, &tv);
        if (nready < 0) {
            if (errno == EINTR)
                continue;
            perror("select");
            break;
        }

        /* Reap exited children */
        {
            pid_t child_pid;
            int status;
            container_record_t *cont, *prev;

            while ((child_pid = waitpid(-1, &status, WNOHANG)) > 0) {
                pthread_mutex_lock(&ctx.metadata_lock);

                /* Find and update container record */
                for (cont = ctx.containers; cont; cont = cont->next) {
                    if (cont->host_pid == child_pid) {
                        if (WIFEXITED(status)) {
                            cont->exit_code = WEXITSTATUS(status);
                            cont->state = CONTAINER_EXITED;
                        } else if (WIFSIGNALED(status)) {
                            cont->exit_signal = WTERMSIG(status);
                            if (cont->exit_signal == SIGKILL) {
                                cont->state = CONTAINER_KILLED;
                            } else {
                                cont->state = CONTAINER_STOPPED;
                            }
                        }
                        break;
                    }
                }

                pthread_mutex_unlock(&ctx.metadata_lock);

                /* Unregister from monitor if available */
                if (ctx.monitor_fd >= 0) {
                    unregister_from_monitor(ctx.monitor_fd, "", child_pid);
                }
            }
        }

        if (!FD_ISSET(ctx.server_fd, &readfds))
            continue;

        /* Accept new connection */
        conn_fd = accept(ctx.server_fd, NULL, NULL);
        if (conn_fd < 0) {
            perror("accept");
            continue;
        }

        memset(buf, 0, sizeof(buf));
        ssize_t n = read(conn_fd, buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            /* Parse and execute the command */
            int cmd_argc = 0;
            char *cmd_argv[16];
            char *cmdcpy = strdup(buf);
            char *saveptr = NULL;
            char *tok;

            tok = strtok_r(cmdcpy, " ", &saveptr);
            while (tok && cmd_argc < 16) {
                cmd_argv[cmd_argc++] = tok;
                tok = strtok_r(NULL, " ", &saveptr);
            }

            if (cmd_argc > 0) {
                memset(&resp, 0, sizeof(resp));
                resp.status = 0;
                snprintf(resp.message, sizeof(resp.message), "OK");

                if ((strcmp(cmd_argv[0], "s") == 0 || strcmp(cmd_argv[0], "start") == 0) ||
                    (strcmp(cmd_argv[0], "r") == 0 || strcmp(cmd_argv[0], "run") == 0)) {
                    if (cmd_argc >= 4) {
                        container_record_t *cont;
                        char stack[STACK_SIZE];
                        child_config_t child_cfg;
                        pid_t child_pid;
                        int pipefd[2];

                        memset(&child_cfg, 0, sizeof(child_cfg));
                        strncpy(child_cfg.id, cmd_argv[1], sizeof(child_cfg.id) - 1);
                        strncpy(child_cfg.rootfs, cmd_argv[2], sizeof(child_cfg.rootfs) - 1);
                        strncpy(child_cfg.command, cmd_argv[3], sizeof(child_cfg.command) - 1);
                        child_cfg.nice_value = 0;
                        child_cfg.log_write_fd = -1;

                        /* Create pipe for log output */
                        if (pipe(pipefd) < 0) {
                            resp.status = -1;
                            snprintf(resp.message, sizeof(resp.message), "pipe failed");
                        } else {
                            child_cfg.log_write_fd = pipefd[1];

                            /* Clone the child */
                            child_pid = clone(child_fn, stack + STACK_SIZE,
                                            CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNS | SIGCHLD,
                                            &child_cfg);

                            close(pipefd[1]); /* Close write end in parent */

                            if (child_pid < 0) {
                                resp.status = -1;
                                snprintf(resp.message, sizeof(resp.message), "clone failed");
                                close(pipefd[0]);
                            } else {
                                /* Create container record */
                                cont = malloc(sizeof(*cont));
                                if (cont) {
                                    memset(cont, 0, sizeof(*cont));
                                    strncpy(cont->id, cmd_argv[1], sizeof(cont->id) - 1);
                                    cont->host_pid = child_pid;
                                    cont->started_at = time(NULL);
                                    cont->state = CONTAINER_RUNNING;
                                    snprintf(cont->log_path, sizeof(cont->log_path), "%s/%s.log",
                                            LOG_DIR, cmd_argv[1]);

                                    pthread_mutex_lock(&ctx.metadata_lock);
                                    cont->next = ctx.containers;
                                    ctx.containers = cont;
                                    pthread_mutex_unlock(&ctx.metadata_lock);

                                    snprintf(resp.message, sizeof(resp.message), 
                                            "Container started with PID %d", child_pid);

                                    /* Start a thread to read from the pipe and push to buffer */
                                    {
                                        pthread_t reader;
                                        pipe_reader_arg_t *reader_arg = malloc(sizeof(*reader_arg));
                                        if (reader_arg) {
                                            reader_arg->ctx = &ctx;
                                            reader_arg->pipe_fd = pipefd[0];
                                            strncpy(reader_arg->container_id, cmd_argv[1], 
                                                   sizeof(reader_arg->container_id) - 1);
                                            pthread_create(&reader, NULL, pipe_reader_thread, reader_arg);
                                            pthread_detach(reader);
                                        }
                                    }
                                } else {
                                    close(pipefd[0]);
                                    resp.status = -1;
                                    snprintf(resp.message, sizeof(resp.message), "malloc failed");
                                }
                            }
                        }
                    } else {
                        resp.status = -1;
                        snprintf(resp.message, sizeof(resp.message), "invalid arguments");
                    }
                } else if (strcmp(cmd_argv[0], "ps") == 0) {
                    container_record_t *cont;
                    char ps_output[4096] = "";

                    pthread_mutex_lock(&ctx.metadata_lock);
                    for (cont = ctx.containers; cont; cont = cont->next) {
                        char line[256];
                        snprintf(line, sizeof(line), 
                                "%s\tPID=%d\tstate=%s\ttime=%ld\n",
                                cont->id, cont->host_pid, state_to_string(cont->state),
                                (long)(time(NULL) - cont->started_at));
                        strncat(ps_output, line, sizeof(ps_output) - strlen(ps_output) - 1);
                    }
                    pthread_mutex_unlock(&ctx.metadata_lock);

                    snprintf(resp.message, sizeof(resp.message), "%s", ps_output);
                } else if (strcmp(cmd_argv[0], "stop") == 0) {
                    if (cmd_argc >= 2) {
                        container_record_t *cont;
                        int found = 0;

                        pthread_mutex_lock(&ctx.metadata_lock);
                        for (cont = ctx.containers; cont; cont = cont->next) {
                            if (strcmp(cont->id, cmd_argv[1]) == 0) {
                                kill(cont->host_pid, SIGTERM);
                                cont->state = CONTAINER_STOPPED;
                                found = 1;
                                break;
                            }
                        }
                        pthread_mutex_unlock(&ctx.metadata_lock);

                        if (found) {
                            snprintf(resp.message, sizeof(resp.message), "Stop signal sent");
                        } else {
                            resp.status = -1;
                            snprintf(resp.message, sizeof(resp.message), "Container not found");
                        }
                    }
                }

                write(conn_fd, &resp, sizeof(resp));
            }

            free(cmdcpy);
        }

        close(conn_fd);
    }

    /* Graceful shutdown */
    fprintf(stderr, "[supervisor] Shutting down...\n");

cleanup:
    bounded_buffer_begin_shutdown(&ctx.log_buffer);
    if (ctx.logger_thread != 0) {
        pthread_join(ctx.logger_thread, NULL);
    }

    if (ctx.server_fd >= 0) {
        close(ctx.server_fd);
        unlink(CONTROL_PATH);
    }

    if (ctx.monitor_fd >= 0) {
        close(ctx.monitor_fd);
    }

    bounded_buffer_destroy(&ctx.log_buffer);
    pthread_mutex_destroy(&ctx.metadata_lock);

    return 0;
}

/*
 * TODO:
 * Implement the client-side control request path.
 *
 * The CLI commands should use a second IPC mechanism distinct from the
 * logging pipe. A UNIX domain socket is the most direct option, but a
 * FIFO or shared memory design is also acceptable if justified.
 */
static int send_control_request(const control_request_t *req)
{
    int fd;
    struct sockaddr_un addr;
    control_response_t resp;
    char cmd_line[CONTROL_MESSAGE_LEN];

    /* Construct the command line */
    switch (req->kind) {
    case CMD_START:
    case CMD_RUN: {
        char cmd_type = (req->kind == CMD_START) ? 's' : 'r';
        snprintf(cmd_line, sizeof(cmd_line), 
                "%c %s %s %s",
                cmd_type, req->container_id, req->rootfs, req->command);
        break;
    }
    case CMD_PS:
        snprintf(cmd_line, sizeof(cmd_line), "ps");
        break;
    case CMD_STOP:
        snprintf(cmd_line, sizeof(cmd_line), "stop %s", req->container_id);
        break;
    case CMD_LOGS:
        snprintf(cmd_line, sizeof(cmd_line), "logs %s", req->container_id);
        break;
    default:
        fprintf(stderr, "Unknown command\n");
        return 1;
    }

    /* Connect to supervisor socket */
    fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, CONTROL_PATH, sizeof(addr.sun_path) - 1);

    if (connect(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("connect to supervisor");
        close(fd);
        return 1;
    }

    /* Send the command */
    if (write(fd, cmd_line, strlen(cmd_line)) < 0) {
        perror("write to supervisor");
        close(fd);
        return 1;
    }

    /* Read the response */
    memset(&resp, 0, sizeof(resp));
    if (read(fd, &resp, sizeof(resp)) > 0) {
        printf("%s\n", resp.message);
        if (resp.status != 0)
            return 1;
    }

    close(fd);
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

    /*
     * TODO:
     * The supervisor should respond with container metadata.
     * Keep the rendering format simple enough for demos and debugging.
     */
    printf("Expected states include: %s, %s, %s, %s, %s\n",
           state_to_string(CONTAINER_STARTING),
           state_to_string(CONTAINER_RUNNING),
           state_to_string(CONTAINER_STOPPED),
           state_to_string(CONTAINER_KILLED),
           state_to_string(CONTAINER_EXITED));
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
