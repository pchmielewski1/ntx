#include "ntx_bencode.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NTX_BE_MAXDICT 4096

typedef struct {
  const uint8_t *buf;
  size_t n;
  size_t pos;
  int max_depth;
  size_t max_size;
  int err;
} be_p;

static void be_free_all(ntx_be *b) {
  if (!b) return;
  for (size_t i = 0; i < b->ne; i++) be_free_all(b->el[i]);
  free(b->el);
  for (size_t i = 0; i < b->nd; i++) {
    be_free_all(b->k[i]);
    be_free_all(b->v[i]);
  }
  free(b->k);
  free(b->v);
  free(b);
}

static ntx_be *be_val(be_p *p, int depth);

static ntx_be *be_val(be_p *p, int depth) {
  if (p->err || p->pos >= p->n) {
    p->err = 1;
    return NULL;
  }
  uint8_t c = p->buf[p->pos];
  ntx_be *node = calloc(1, sizeof *node);
  if (!node) {
    p->err = 1;
    return NULL;
  }
  node->start = p->pos;

  if (c == 'i') {
    size_t e = p->pos + 1;
    while (e < p->n && p->buf[e] != 'e') e++;
    if (e >= p->n) {
      free(node);
      p->err = 1;
      return NULL;
    }
    size_t s = p->pos + 1;
    int neg = 0;
    if (s < e && p->buf[s] == '-') {
      neg = 1;
      s++;
    }
    size_t dlen = e - s;
    if (dlen == 0 || dlen > 19) {
      free(node);
      p->err = 1;
      return NULL;
    }
    if (dlen > 1 && p->buf[s] == '0') {
      free(node);
      p->err = 1;
      return NULL;
    }
    int64_t v = 0;
    for (size_t i = s; i < e; i++) {
      uint8_t d = p->buf[i];
      if (d < '0' || d > '9') {
        free(node);
        p->err = 1;
        return NULL;
      }
      if (v > (INT64_MAX - 9) / 10) {
        free(node);
        p->err = 1;
        return NULL;
      }
      v = v * 10 + (int64_t)(d - '0');
    }
    node->t = NTX_BE_INT;
    node->i = neg ? -v : v;
    p->pos = e + 1;
    node->end = p->pos;
    return node;
  }

  if (c >= '0' && c <= '9') {
    size_t s = p->pos;
    if (c == '0') {
      if (p->pos + 1 >= p->n || p->buf[p->pos + 1] != ':') {
        free(node);
        p->err = 1;
        return NULL;
      }
      size_t data = p->pos + 2;
      if (data > p->n) {
        free(node);
        p->err = 1;
        return NULL;
      }
      node->t = NTX_BE_STR;
      node->sp = (uint8_t *)p->buf + data;
      node->sn = 0;
      node->start = data;
      p->pos = data;
      node->end = p->pos;
      return node;
    }
    size_t e = s;
    while (e < p->n && p->buf[e] >= '0' && p->buf[e] <= '9') e++;
    if (e >= p->n || p->buf[e] != ':') {
      free(node);
      p->err = 1;
      return NULL;
    }
    size_t len = 0;
    for (size_t i = s; i < e; i++) {
      if (len > (SIZE_MAX - (size_t)(p->buf[i] - '0')) / 10) {
        free(node);
        p->err = 1;
        return NULL;
      }
      len = len * 10 + (size_t)(p->buf[i] - '0');
    }
    if (len > p->max_size) {
      free(node);
      p->err = 1;
      return NULL;
    }
    size_t data = e + 1;
    if (data + len > p->n) {
      free(node);
      p->err = 1;
      return NULL;
    }
    node->t = NTX_BE_STR;
    node->sp = (uint8_t *)p->buf + data;
    node->sn = len;
    node->start = data;
    p->pos = data + len;
    node->end = p->pos;
    return node;
  }

  if (c == 'l' || c == 'd') {
    if (depth >= p->max_depth) {
      free(node);
      p->err = 1;
      return NULL;
    }
    node->t = (c == 'l') ? NTX_BE_LIST : NTX_BE_DICT;
    p->pos++;
    for (;;) {
      if (p->err || p->pos >= p->n) {
        be_free_all(node);
        p->err = 1;
        return NULL;
      }
      uint8_t nc = p->buf[p->pos];
      if (nc == 'e') {
        p->pos++;
        break;
      }
      ntx_be *child = be_val(p, depth + 1);
      if (!child) {
        be_free_all(node);
        p->err = 1;
        return NULL;
      }
      if (node->t == NTX_BE_LIST) {
        ntx_be **ne2 = realloc(node->el, (node->ne + 1) * sizeof *node->el);
        if (!ne2) {
          be_free_all(child);
          be_free_all(node);
          p->err = 1;
          return NULL;
        }
        node->el = ne2;
        node->el[node->ne] = child;
        node->ne++;
      } else {
        if (child->t != NTX_BE_STR) {
          be_free_all(child);
          be_free_all(node);
          p->err = 1;
          return NULL;
        }
        if (node->nd >= NTX_BE_MAXDICT) {
          be_free_all(child);
          be_free_all(node);
          p->err = 1;
          return NULL;
        }
        ntx_be *val = be_val(p, depth + 1);
        if (!val) {
          be_free_all(child);
          be_free_all(node);
          p->err = 1;
          return NULL;
        }
        ntx_be **nk = realloc(node->k, (node->nd + 1) * sizeof *node->k);
        if (!nk) {
          be_free_all(child);
          be_free_all(val);
          be_free_all(node);
          p->err = 1;
          return NULL;
        }
        node->k = nk;
        ntx_be **nv = realloc(node->v, (node->nd + 1) * sizeof *node->v);
        if (!nv) {
          be_free_all(child);
          be_free_all(val);
          be_free_all(node);
          p->err = 1;
          return NULL;
        }
        node->v = nv;
        node->k[node->nd] = child;
        node->v[node->nd] = val;
        node->nd++;
      }
    }
    node->end = p->pos;
    return node;
  }

  free(node);
  p->err = 1;
  return NULL;
}

int ntx_be_parse(const uint8_t *buf, size_t n, ntx_be *out, size_t *consumed, int max_depth, size_t max_size) {
  be_p p = {buf, n, 0, max_depth, max_size, 0};
  ntx_be *node = be_val(&p, 0);
  if (!node || p.pos != n) {
    if (node) be_free_all(node);
    out->t = NTX_BE_INT;
    out->i = 0;
    out->sp = 0;
    out->sn = 0;
    out->el = 0;
    out->ne = 0;
    out->k = 0;
    out->v = 0;
    out->nd = 0;
    out->start = 0;
    out->end = 0;
    if (consumed) *consumed = 0;
    return -1;
  }
  *out = *node;
  free(node);
  if (consumed) *consumed = p.pos;
  return 0;
}

void ntx_be_free(ntx_be *b) {
  if (!b) return;
  for (size_t i = 0; i < b->ne; i++) be_free_all(b->el[i]);
  free(b->el);
  for (size_t i = 0; i < b->nd; i++) {
    be_free_all(b->k[i]);
    be_free_all(b->v[i]);
  }
  free(b->k);
  free(b->v);
}

const ntx_be *ntx_be_dict_get(const ntx_be *d, const char *key) {
  if (!d || d->t != NTX_BE_DICT) return NULL;
  size_t klen = strlen(key);
  for (size_t i = 0; i < d->nd; i++) {
    const ntx_be *k = d->k[i];
    if (k->t == NTX_BE_STR && k->sn == klen && memcmp(k->sp, key, klen) == 0) return d->v[i];
  }
  return NULL;
}

typedef struct {
  uint8_t *d;
  size_t n;
  size_t cap;
  int err;
} be_w;

static void be_put(be_w *w, const uint8_t *p, size_t n) {
  if (w->err) return;
  if (w->n + n > w->cap) {
    size_t nc = w->cap ? w->cap * 2 : 256;
    while (nc < w->n + n) nc *= 2;
    uint8_t *nd = realloc(w->d, nc);
    if (!nd) {
      w->err = 1;
      return;
    }
    w->d = nd;
    w->cap = nc;
  }
  memcpy(w->d + w->n, p, n);
  w->n += n;
}

static void be_encode_val(be_w *w, const ntx_be *b) {
  if (w->err) return;
  switch (b->t) {
  case NTX_BE_INT: {
    char tmp[32];
    int len = snprintf(tmp, sizeof tmp, "i%lld", (long long)b->i);
    be_put(w, (const uint8_t *)tmp, (size_t)len);
    be_put(w, (const uint8_t *)"e", 1);
    break;
  }
  case NTX_BE_STR: {
    char tmp[32];
    int len = snprintf(tmp, sizeof tmp, "%zu", b->sn);
    be_put(w, (const uint8_t *)tmp, (size_t)len);
    be_put(w, (const uint8_t *)":", 1);
    be_put(w, b->sp, b->sn);
    break;
  }
  case NTX_BE_LIST: {
    be_put(w, (const uint8_t *)"l", 1);
    for (size_t i = 0; i < b->ne; i++) be_encode_val(w, b->el[i]);
    be_put(w, (const uint8_t *)"e", 1);
    break;
  }
  case NTX_BE_DICT: {
    size_t nd = b->nd;
    size_t *idx = 0;
    if (nd) {
      idx = malloc(nd * sizeof *idx);
      if (!idx) {
        w->err = 1;
        return;
      }
      for (size_t i = 0; i < nd; i++) idx[i] = i;
      for (size_t i = 0; i < nd; i++) {
        for (size_t j = i + 1; j < nd; j++) {
          const ntx_be *a = b->k[idx[i]];
          const ntx_be *c = b->k[idx[j]];
          size_t m = a->sn < c->sn ? a->sn : c->sn;
          int cmp = memcmp(a->sp, c->sp, m);
          if (cmp == 0)
            cmp = (a->sn < c->sn) ? -1 : (a->sn > c->sn) ? 1 : 0;
          if (cmp > 0) {
            size_t t = idx[i];
            idx[i] = idx[j];
            idx[j] = t;
          }
        }
      }
    }
    be_put(w, (const uint8_t *)"d", 1);
    for (size_t i = 0; i < nd; i++) {
      be_encode_val(w, b->k[idx[i]]);
      be_encode_val(w, b->v[idx[i]]);
    }
    free(idx);
    be_put(w, (const uint8_t *)"e", 1);
    break;
  }
  }
}

int ntx_be_encode(const ntx_be *b, uint8_t *out, size_t cap, size_t *written) {
  be_w w = {0, 0, 0, 0};
  be_encode_val(&w, b);
  if (w.err || w.n > cap) {
    free(w.d);
    if (written) *written = 0;
    return -1;
  }
  if (out) memcpy(out, w.d, w.n);
  free(w.d);
  if (written) *written = w.n;
  return 0;
}

/* be_dict_* + be_val_end split out of ntx_ext.c. */

int be_dict_init(be_dict *d, size_t cap) {
    d->k = malloc(cap ? cap * sizeof *d->k : 1);
    d->v = malloc(cap ? cap * sizeof *d->v : 1);
    d->kp = malloc(cap ? cap * sizeof *d->kp : 1);
    d->vp = malloc(cap ? cap * sizeof *d->vp : 1);
    d->n = 0;
    d->cap = cap;
    return (d->k && d->v && d->kp && d->vp) ? 0 : -1;
}

void be_dict_free(be_dict *d) {
    free(d->k);
    free(d->v);
    free(d->kp);
    free(d->vp);
    d->k = 0;
    d->v = 0;
    d->kp = 0;
    d->vp = 0;
    d->n = 0;
    d->cap = 0;
}

int be_dict_add(be_dict *d, ntx_be key, ntx_be val) {
    if (d->n >= d->cap) return -1;
    size_t i = d->n++;
    d->k[i] = key;
    d->v[i] = val;
    d->kp[i] = &d->k[i];
    d->vp[i] = &d->v[i];
    return 0;
}

int be_val_end(const uint8_t *buf, size_t n, size_t *end) {
    size_t pos = 0;
    int depth = 0;
    while (pos < n) {
        uint8_t c = buf[pos];
        if (c == 'i') {
            pos++;
            while (pos < n && buf[pos] != 'e') pos++;
            if (pos >= n) return -1;
            pos++;
        } else if (c >= '0' && c <= '9') {
            size_t len = 0;
            while (pos < n && buf[pos] >= '0' && buf[pos] <= '9') {
                len = len * 10 + (size_t)(buf[pos] - '0');
                pos++;
            }
            if (pos >= n || buf[pos] != ':') return -1;
            pos++;
            if (len > n - pos) return -1;
            pos += len;
        } else if (c == 'l' || c == 'd') {
            depth++;
            pos++;
        } else if (c == 'e') {
            pos++;
            depth--;
            if (depth < 0) return -1;
            if (depth == 0) {
                *end = pos;
                return 0;
            }
        } else {
            return -1;
        }
    }
    return -1;
}
