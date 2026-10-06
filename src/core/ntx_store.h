#ifndef NTX_STORE_H
#define NTX_STORE_H

#include <stddef.h>
#include <stdint.h>

typedef struct ntx_be ntx_be;

typedef struct {
    int fd;
    uint64_t start;
    uint64_t len;
} ntx_store_part;

typedef struct {
    const char *path;
    uint64_t start;
    uint64_t len;
} ntx_store_part_spec;

typedef struct ntx_store {
    int fd;
    uint64_t size;
    uint32_t ps;
    uint8_t *pmap;
    uint32_t np;
    ntx_store_part *parts;
    int nparts;
    uint8_t existed;
} ntx_store;

int ntx_store_open(ntx_store *st, const char *path, uint64_t size, uint32_t ps);
int ntx_store_open_parts(ntx_store *st, const ntx_store_part_spec *specs, int nspecs, uint64_t size,
                         uint32_t ps);
void ntx_store_close(ntx_store *st);
uint32_t ntx_store_pl(const ntx_store *st, uint32_t i);
int ntx_store_write(ntx_store *st, uint32_t i, uint32_t off, const void *buf, size_t len);
int ntx_store_read(const ntx_store *st, uint32_t i, uint32_t off, void *buf, size_t len);
int ntx_store_complete(ntx_store *st, uint32_t i, const uint8_t h20[20]);
uint8_t ntx_store_pmap(const ntx_store *st, uint32_t i);
uint64_t ntx_store_verified_bytes(const ntx_store *st);

/* Implemented in ntx_store.c: ntx_store_file_rel/path_append/size_of */
int ntx_store_size_of(const ntx_be *info, uint64_t *out);
int ntx_store_path_append(char *out, size_t cap, size_t *o, const uint8_t *sp, size_t sn);
int ntx_store_file_rel(char *out, size_t cap, const ntx_be *name, const ntx_be *path);
#endif
