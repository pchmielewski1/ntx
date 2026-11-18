#ifndef NTX_CLI_H
#define NTX_CLI_H

#include <stdio.h>
#include "ntx_stats.h"

/* Build one human-readable status line (wget-style). Returns bytes written. */
size_t ntx_cli_status_format(const ntx_stats *st, char *out, size_t cap);

/* Update progress on fp (stderr recommended). Uses \r on TTY. */
void ntx_cli_status_update(const ntx_stats *st, FILE *fp, int *needs_nl);

/* Final newline + summary when the session ends. */
void ntx_cli_status_finish(const ntx_stats *st, FILE *fp, int needs_nl);

/* R26: the ONE "close the status line" operation. Ends the live tty line the
 * update path drew in place, so anything printed next starts at column 0, and
 * spends the pending-newline flag with it (no extra blank line later). A no-op
 * when no line is open or when the line went to a pipe (already terminated).
 * Registered with ntx_diag_set_close_hook() and called directly by the magnet
 * print — the two spellings of "close the line" the code used to carry. */
void ntx_cli_close_status_line(void);

#endif
