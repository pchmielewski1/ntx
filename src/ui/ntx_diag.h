#ifndef NTX_DIAG_H
#define NTX_DIAG_H

#include <stdarg.h>
#include <stdio.h>

/* Open/close mirror file for --verbose / --log=. stderr unchanged. */
int ntx_diag_open(const char *path);
void ntx_diag_close(void);
FILE *ntx_diag_fp(void);

/* fprintf to stderr and to the diag file (if open). */
void ntx_diag(const char *fmt, ...);
void ntx_diagv(const char *fmt, va_list ap);

#endif
