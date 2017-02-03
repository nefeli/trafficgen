#ifndef __log_h__
#define __log_h__
#if DAEMON
#include <syslog.h>
#define logmsg(priority, fmt, ...) syslog(priority, fmt, ##__VA_ARGS__)
#else
#define logmsg(priority, fmt, ...) printf(fmt "\n", ##__VA_ARGS__)
#endif

typedef struct rte_mbuf **mbuf_array_t;

struct rte_mbuf tx_mbuf_template;

#if DAEMON
static void
setup_daemon(void)
{
    FILE *f;
    pid_t pid;

    pid = fork();

    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }
    if (setsid() < 0) {
        exit(EXIT_FAILURE);
    }
    pid = fork();
    if (pid < 0) {
        exit(EXIT_FAILURE);
    }
    if (pid > 0) {
        exit(EXIT_SUCCESS);
    }

    umask(0);

    f = fopen("./pktgen.pid", "w+");

    if (f == NULL) {
        exit(EXIT_FAILURE);
    }

    if (fprintf(f, "%d", getpid()) <= 0) {
        fclose(f);
        exit(EXIT_FAILURE);
    }

    if ((chdir("/")) < 0) {
        exit(EXIT_FAILURE);
    }

    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);

    openlog("pktgen", LOG_PID, LOG_DAEMON);
}
#endif
#endif
