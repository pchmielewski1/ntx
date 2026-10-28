/* tscale.h helper contract: ts_ms(base) = base * scale, where scale comes from
 * NTX_TEST_TIMEOUT_SCALE parsed once (first call). Missing env or garbage -> 1.
 * Each case runs in a forked child so the one-shot parse cache starts fresh
 * and the parent's own environment never influences the assertions. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include "tscale.h"

static int fails;

static void check(int cond, const char *name) {
    if (cond) printf("PASS %s\n", name);
    else { printf("FAIL %s\n", name); fails = 1; }
}

/* Fork a child that (re)sets NTX_TEST_TIMEOUT_SCALE (envval NULL -> unset),
 * then calls ts_ms(100) as its first helper use and writes the result back. */
static long probe(const char *envval, int *ok) {
    int pfd[2];
    *ok = 0;
    if (pipe(pfd) != 0) { fprintf(stderr, "pipe fail\n"); fails = 1; return -1; }
    pid_t pid = fork();
    if (pid < 0) { fprintf(stderr, "fork fail\n"); fails = 1; close(pfd[0]); close(pfd[1]); return -1; }
    if (pid == 0) {
        close(pfd[0]);
        if (envval) setenv("NTX_TEST_TIMEOUT_SCALE", envval, 1);
        else unsetenv("NTX_TEST_TIMEOUT_SCALE");
        char buf[32];
        int n = snprintf(buf, sizeof buf, "%ld", ts_ms(100));
        if (n > 0) {
            ssize_t w = write(pfd[1], buf, (size_t)n);
            (void)w;
        }
        close(pfd[1]);
        _exit(0);
    }
    close(pfd[1]);
    char buf[32];
    memset(buf, 0, sizeof buf);
    ssize_t r = read(pfd[0], buf, sizeof buf - 1);
    close(pfd[0]);
    int status = 0;
    if (waitpid(pid, &status, 0) != pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0 || r <= 0) {
        fprintf(stderr, "probe child failed (%s)\n", envval ? envval : "<unset>");
        fails = 1;
        return -1;
    }
    *ok = 1;
    return strtol(buf, NULL, 10);
}

int main(void) {
    int ok;
    long v;

    v = probe("5", &ok);
    check(ok && v == 500, "scale5-ts_ms100-is500");

    v = probe(NULL, &ok);
    check(ok && v == 100, "unset-ts_ms100-is100");

    v = probe("abc", &ok);
    check(ok && v == 100, "garbage-ts_ms100-is100");

    return fails;
}
