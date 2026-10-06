#include "../src/proto/ntx_bencode.c"
#include "../src/ui/ntx_diag.c"
#include "util.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static uint8_t *keep = 0;
static size_t keep_n = 0;

static ntx_be load(const char *path) {
  size_t n;
  uint8_t *buf = read_file(path, &n);
  ntx_be b;
  size_t consumed;
  int rc = ntx_be_parse(buf, n, &b, &consumed, 32, (size_t)(1 << 20));
  if (rc != 0) {
    fprintf(stderr, "FAIL parse %s\n", path);
    exit(1);
  }
  if (consumed != n) {
    fprintf(stderr, "FAIL consumed %s\n", path);
    exit(1);
  }
  free(keep);
  keep = buf;
  keep_n = n;
  return b;
}

static int enc_eq_file(const ntx_be *b, uint8_t *out, size_t cap, size_t *w) {
  if (ntx_be_encode(b, out, cap, w) != 0) return -1;
  if (*w != keep_n || memcmp(out, keep, *w) != 0) return -1;
  return 0;
}

int main(void) {
  uint8_t out[4096];
  size_t w;

  {
    ntx_be b = load("test/vectors/bencode/spam.encoded");
    if (b.t != NTX_BE_DICT) {
      fprintf(stderr, "FAIL spam-dict\n");
      return 1;
    }
    const ntx_be *v = ntx_be_dict_get(&b, "spam");
    if (!v || v->t != NTX_BE_STR || v->sn != 4 || memcmp(v->sp, "eggs", 4) != 0) {
      fprintf(stderr, "FAIL spam-eggs\n");
      return 1;
    }
    if (b.start != 0 || b.end != keep_n) {
      fprintf(stderr, "FAIL spam-startend\n");
      return 1;
    }
    if (enc_eq_file(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL spam-enc\n");
      return 1;
    }
    ntx_be_free(&b);
    printf("PASS spam\n");
  }

  {
    ntx_be b = load("test/vectors/bencode/nested.encoded");
    if (b.t != NTX_BE_DICT) {
      fprintf(stderr, "FAIL nested-dict\n");
      return 1;
    }
    const ntx_be *col = ntx_be_dict_get(&b, "col");
    if (!col || col->t != NTX_BE_LIST || col->ne != 1 || col->el[0]->t != NTX_BE_STR || col->el[0]->sn != 4 ||
        memcmp(col->el[0]->sp, "spam", 4) != 0) {
      fprintf(stderr, "FAIL nested-col\n");
      return 1;
    }
    const ntx_be *foo = ntx_be_dict_get(&b, "foo");
    if (!foo || foo->t != NTX_BE_INT || foo->i != 42) {
      fprintf(stderr, "FAIL nested-foo\n");
      return 1;
    }
    if (enc_eq_file(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL nested-enc\n");
      return 1;
    }
    ntx_be_free(&b);
    printf("PASS nested\n");
  }

  {
    ntx_be b = load("test/vectors/bencode/torrent.encoded");
    if (b.t != NTX_BE_DICT) {
      fprintf(stderr, "FAIL torrent-dict\n");
      return 1;
    }
    const ntx_be *fn = ntx_be_dict_get(&b, "filename");
    if (!fn || fn->t != NTX_BE_STR || fn->sn != 12 || memcmp(fn->sp, "my-file.text", 12) != 0) {
      fprintf(stderr, "FAIL torrent-filename\n");
      return 1;
    }
    if (fn->end - fn->start != 12) {
      fprintf(stderr, "FAIL torrent-filename-startend\n");
      return 1;
    }
    const ntx_be *spam = ntx_be_dict_get(&b, "spam");
    if (!spam || spam->t != NTX_BE_INT || spam->i != 12345) {
      fprintf(stderr, "FAIL torrent-spam\n");
      return 1;
    }
    const ntx_be *modi = ntx_be_dict_get(&b, "modi");
    if (!modi || modi->t != NTX_BE_STR || modi->sn != 19 || memcmp(modi->sp, "2009-04-02T11:36:53", 19) != 0) {
      fprintf(stderr, "FAIL torrent-modi\n");
      return 1;
    }
    if (b.start != 0 || b.end != keep_n) {
      fprintf(stderr, "FAIL torrent-startend\n");
      return 1;
    }
    if (enc_eq_file(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL torrent-enc\n");
      return 1;
    }
    ntx_be_free(&b);
    printf("PASS torrent\n");
  }

  {
    ntx_be b = load("test/vectors/bencode/empty_dict.encoded");
    if (b.t != NTX_BE_DICT || b.nd != 0) {
      fprintf(stderr, "FAIL empty_dict\n");
      return 1;
    }
    if (enc_eq_file(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL empty_dict-enc\n");
      return 1;
    }
    ntx_be_free(&b);
    printf("PASS empty_dict\n");
  }

  {
    ntx_be b = load("test/vectors/bencode/negint.encoded");
    if (b.t != NTX_BE_INT || b.i != -123) {
      fprintf(stderr, "FAIL negint\n");
      return 1;
    }
    if (b.start != 0 || b.end != keep_n) {
      fprintf(stderr, "FAIL negint-startend\n");
      return 1;
    }
    if (enc_eq_file(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL negint-enc\n");
      return 1;
    }
    ntx_be_free(&b);
    printf("PASS negint\n");
  }

  {
    ntx_be b = load("test/vectors/bencode/list.encoded");
    if (b.t != NTX_BE_LIST || b.ne != 2) {
      fprintf(stderr, "FAIL list\n");
      return 1;
    }
    if (b.el[0]->t != NTX_BE_STR || b.el[0]->sn != 4 || memcmp(b.el[0]->sp, "spam", 4) != 0) {
      fprintf(stderr, "FAIL list-0\n");
      return 1;
    }
    if (b.el[1]->t != NTX_BE_STR || b.el[1]->sn != 4 || memcmp(b.el[1]->sp, "eggs", 4) != 0) {
      fprintf(stderr, "FAIL list-1\n");
      return 1;
    }
    if (enc_eq_file(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL list-enc\n");
      return 1;
    }
    ntx_be_free(&b);
    printf("PASS list\n");
  }

  {
    ntx_be b = load("test/vectors/bencode/unsorted.encoded");
    if (b.t != NTX_BE_DICT || b.nd != 3) {
      fprintf(stderr, "FAIL unsorted-dict\n");
      return 1;
    }
    const ntx_be *bar = ntx_be_dict_get(&b, "bar");
    const ntx_be *baz = ntx_be_dict_get(&b, "baz");
    const ntx_be *quux = ntx_be_dict_get(&b, "quux");
    if (!bar || bar->t != NTX_BE_INT || bar->i != 2) {
      fprintf(stderr, "FAIL unsorted-bar\n");
      return 1;
    }
    if (!baz || baz->t != NTX_BE_INT || baz->i != 99) {
      fprintf(stderr, "FAIL unsorted-baz\n");
      return 1;
    }
    if (!quux || quux->t != NTX_BE_LIST || quux->ne != 2) {
      fprintf(stderr, "FAIL unsorted-quux\n");
      return 1;
    }
    if (quux->el[0]->sn != 4 || memcmp(quux->el[0]->sp, "eggs", 4) != 0) {
      fprintf(stderr, "FAIL unsorted-quux-0\n");
      return 1;
    }
    if (quux->el[1]->sn != 3 || memcmp(quux->el[1]->sp, "xyz", 3) != 0) {
      fprintf(stderr, "FAIL unsorted-quux-1\n");
      return 1;
    }
    if (ntx_be_encode(&b, out, sizeof out, &w) != 0) {
      fprintf(stderr, "FAIL unsorted-enc\n");
      return 1;
    }
    if (memcmp(out, "d3:bar", 5) != 0) {
      fprintf(stderr, "FAIL unsorted-sorted\n");
      return 1;
    }
    if (w == keep_n && memcmp(out, keep, w) == 0) {
      fprintf(stderr, "FAIL unsorted-unchanged\n");
      return 1;
    }
    ntx_be b2;
    size_t c2;
    if (ntx_be_parse(out, w, &b2, &c2, 32, (size_t)(1 << 20)) != 0) {
      fprintf(stderr, "FAIL unsorted-rt-parse\n");
      return 1;
    }
    uint8_t out2[4096];
    size_t w2;
    if (ntx_be_encode(&b2, out2, sizeof out2, &w2) != 0 || w2 != w || memcmp(out, out2, w) != 0) {
      fprintf(stderr, "FAIL unsorted-rt-stable\n");
      return 1;
    }
    ntx_be_free(&b2);
    ntx_be_free(&b);
    printf("PASS unsorted\n");
  }

  const char *mal[] = {
      "test/vectors/bencode/bad_len.encoded",
      "test/vectors/bencode/neg_len.encoded",
      "test/vectors/bencode/unclosed.encoded",
      "test/vectors/bencode/trailing.encoded",
      "test/vectors/bencode/badkey.encoded",
      "test/vectors/bencode/depth.encoded",
  };
  for (size_t i = 0; i < sizeof mal / sizeof mal[0]; i++) {
    size_t n;
    uint8_t *buf = read_file(mal[i], &n);
    ntx_be b;
    size_t consumed;
    int rc = ntx_be_parse(buf, n, &b, &consumed, 32, (size_t)(1 << 20));
    if (rc != -1) {
      fprintf(stderr, "FAIL malformed-accepted %s\n", mal[i]);
      free(buf);
      return 1;
    }
    free(buf);
  }
  printf("PASS malformed\n");

  printf("ALL PASS\n");
  return 0;
}
