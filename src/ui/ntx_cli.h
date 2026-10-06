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

#endif
