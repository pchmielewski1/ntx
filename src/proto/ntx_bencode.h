#ifndef NTX_BENCODE_H
#define NTX_BENCODE_H

#include <stddef.h>
#include <stdint.h>

typedef enum { NTX_BE_INT, NTX_BE_STR, NTX_BE_LIST, NTX_BE_DICT } ntx_be_t;

typedef struct ntx_be {
  ntx_be_t t;
  int64_t i;
  uint8_t *sp;
  size_t sn;
  struct ntx_be **el;
  size_t ne;
  struct ntx_be **k;
  struct ntx_be **v;
  size_t nd;
  size_t start;
  size_t end;
} ntx_be;

int ntx_be_parse(const uint8_t *buf, size_t n, ntx_be *out, size_t *consumed, int max_depth, size_t max_size);
void ntx_be_free(ntx_be *b);
const ntx_be *ntx_be_dict_get(const ntx_be *d, const char *key);
int ntx_be_encode(const ntx_be *b, uint8_t *out, size_t cap, size_t *written);

typedef struct {
    ntx_be *k;
    ntx_be *v;
    ntx_be **kp;
    ntx_be **vp;
    size_t n;
    size_t cap;
} be_dict;

int be_dict_init(be_dict *d, size_t cap);
void be_dict_free(be_dict *d);
int be_dict_add(be_dict *d, ntx_be key, ntx_be val);
int be_val_end(const uint8_t *buf, size_t n, size_t *end);

/* be_dict (struct) + be_dict_init/free/add + be_val_end — split out of ntx_ext.c. */
#endif
