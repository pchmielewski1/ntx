#ifndef NTX_DIAG_H
#define NTX_DIAG_H

#include <stdarg.h>
#include <stdio.h>

/* Open/close mirror file for --verbose / --log=. stderr unchanged. */
int ntx_diag_open(const char *path);
void ntx_diag_close(void);
FILE *ntx_diag_fp(void);

/* R26: the ONE hook that closes a live status line. The CLI redraws its line in
 * place (\r + clear line), so a diagnostic written while that line is open lands
 * ON it — the two texts run together and the next redraw erases the message.
 * ntx_diag therefore calls this before its own bytes; the CLI's implementation
 * ends the line it owns and is a no-op when nothing is open. Registered once by
 * ntx_main; NULL in a build with no CLI (and in the test TUs that stub diag). */
void ntx_diag_set_close_hook(void (*hook)(void));

/* The same closer, for the one caller that prints something of its own right
 * after closing it (the magnet and the share-failure line in ntx_main.c), so
 * the program carries exactly ONE spelling of "the live line is over". A no-op
 * when no hook is registered or no line is open. */
void ntx_diag_close_status_line(void);

/* fprintf to stderr and to the diag file (if open). */
void ntx_diag(const char *fmt, ...);
void ntx_diagv(const char *fmt, va_list ap);

#endif
