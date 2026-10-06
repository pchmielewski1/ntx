#include "ntx_diag.h"

#include <stdio.h>
#include <stdlib.h>

static FILE *g_diag;

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
