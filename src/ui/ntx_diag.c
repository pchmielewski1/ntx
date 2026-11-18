#include "ntx_diag.h"

#include <stdio.h>
#include <stdlib.h>

static FILE *g_diag;
static void (*g_diag_close_line)(void);

void ntx_diag_set_close_hook(void (*hook)(void)) { g_diag_close_line = hook; }

/* The closer, for the one caller that prints something of its own right after
 * closing (the magnet and the share-failure line in ntx_main.c), so the program
 * carries exactly one spelling of "the live line is over". */
void ntx_diag_close_status_line(void) {
    if (g_diag_close_line) g_diag_close_line();
}

int ntx_diag_open(const char *path) {
    if (!path || !*path) return -1;
    if (g_diag) {
        fclose(g_diag);
        g_diag = NULL;
    }
    g_diag = fopen(path, "w");
    if (!g_diag) return -1;
    setvbuf(g_diag, NULL, _IONBF, 0);
    return 0;
}

void ntx_diag_close(void) {
    if (!g_diag) return;
    fflush(g_diag);
    fclose(g_diag);
    g_diag = NULL;
}

FILE *ntx_diag_fp(void) { return g_diag; }

void ntx_diagv(const char *fmt, va_list ap) {
    va_list ap2;
    va_copy(ap2, ap);
    /* R26: whatever live line the CLI has open goes first, so this message
     * always starts at column 0. The hook is a no-op when none is open and
     * writes nothing to a pipe, so plain output is byte-for-byte unchanged. */
    if (g_diag_close_line) g_diag_close_line();
    vfprintf(stderr, fmt, ap);
    if (g_diag) vfprintf(g_diag, fmt, ap2);
    va_end(ap2);
}

void ntx_diag(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    ntx_diagv(fmt, ap);
    va_end(ap);
}
