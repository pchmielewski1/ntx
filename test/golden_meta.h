/* test/golden_meta.h — minimal JSON DOM for golden fixture .meta.json sidecars.
 *
 * C11 + libc only, zero external deps. Parses the JSON subset used by the
 * golden fixture meta sidecars under test/fixtures/ (announce, dht, pe):
 * objects, arrays, strings
 * (escapes \" \\ \/ \b \f \n \r \t \uXXXX), integers, booleans, null.
 * Intended for inclusion in standalone test TUs (single-file compile).
 */
#ifndef TEST_GOLDEN_META_H
#define TEST_GOLDEN_META_H

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef enum { GM_NULL = 0, GM_BOOL, GM_NUM, GM_STR, GM_ARR, GM_OBJ } gm_t;

typedef struct gm {
    gm_t t;
    int b;
    int64_t num;
    char *str;
    struct gm **el; size_t ne;
    char **k; struct gm **v; size_t nd;
} gm;

static int __attribute__((unused)) gm_parse(const char *s, size_t n, gm *out);
static void __attribute__((unused)) gm_free(gm *v);
static const gm *__attribute__((unused)) gm_get(const gm *o, const char *key);
static int __attribute__((unused)) gm_num(const gm *v, int64_t *out);
static int __attribute__((unused)) gm_str(const gm *v, const char **out);
static int __attribute__((unused)) gm_bool(const gm *v, int *out);

static const char *g_p;
static const char *g_end;
static int g_err;

static void gskip(void) {
    while (g_p < g_end) {
        char c = *g_p;
        if (c == ' ' || c == '\t' || c == '\n' || c == '\r') g_p++;
        else break;
    }
}

static int gval(gm *out);

static char *gstr(void) {
    if (g_p >= g_end || *g_p != '"') { g_err = 1; return NULL; }
    g_p++;
    size_t cap = 16, len = 0;
    char *s = malloc(cap);
    if (!s) { g_err = 1; return NULL; }
    while (g_p < g_end && *g_p != '"') {
        char c = *g_p++;
        if (c == '\\') {
            if (g_p >= g_end) { g_err = 1; free(s); return NULL; }
            char e = *g_p++;
            switch (e) {
                case '"': c = '"'; break;
                case '\\': c = '\\'; break;
                case '/': c = '/'; break;
                case 'b': c = '\b'; break;
                case 'f': c = '\f'; break;
                case 'n': c = '\n'; break;
                case 'r': c = '\r'; break;
                case 't': c = '\t'; break;
                case 'u': {
                    if ((size_t)(g_end - g_p) < 4) { g_err = 1; free(s); return NULL; }
                    unsigned cp = 0;
                    for (int i = 0; i < 4; i++) {
                        char h = g_p[i];
                        cp <<= 4;
                        if (h >= '0' && h <= '9') cp |= (unsigned)(h - '0');
                        else if (h >= 'a' && h <= 'f') cp |= (unsigned)(h - 'a' + 10);
                        else if (h >= 'A' && h <= 'F') cp |= (unsigned)(h - 'A' + 10);
                        else { g_err = 1; free(s); return NULL; }
                    }
                    g_p += 4;
                    unsigned add = cp < 0x80 ? 1 : (cp < 0x800 ? 2 : 3);
                    if (len + add + 1 > cap) {
                        while (len + add + 1 > cap) cap *= 2;
                        char *ns = realloc(s, cap);
                        if (!ns) { g_err = 1; free(s); return NULL; }
                        s = ns;
                    }
                    if (cp < 0x80) {
                        s[len++] = (char)cp;
                    } else if (cp < 0x800) {
                        s[len++] = (char)(0xC0 | (cp >> 6));
                        s[len++] = (char)(0x80 | (cp & 0x3F));
                    } else {
                        s[len++] = (char)(0xE0 | (cp >> 12));
                        s[len++] = (char)(0x80 | ((cp >> 6) & 0x3F));
                        s[len++] = (char)(0x80 | (cp & 0x3F));
                    }
                    continue;
                }
                default: g_err = 1; free(s); return NULL;
            }
        }
        if (len + 2 > cap) {
            while (len + 2 > cap) cap *= 2;
            char *ns = realloc(s, cap);
            if (!ns) { g_err = 1; free(s); return NULL; }
            s = ns;
        }
        s[len++] = c;
    }
    if (g_p >= g_end) { g_err = 1; free(s); return NULL; }
    g_p++;
    s[len] = '\0';
    return s;
}

static int gnum(gm *out) {
    const char *s = g_p;
    if (g_p < g_end && (*g_p == '-' || *g_p == '+')) g_p++;
    if (g_p >= g_end || !(*g_p >= '0' && *g_p <= '9')) { g_err = 1; return 0; }
    while (g_p < g_end && *g_p >= '0' && *g_p <= '9') g_p++;
    if (g_p < g_end && (*g_p == '.' || *g_p == 'e' || *g_p == 'E')) { g_err = 1; return 0; }
    size_t l = (size_t)(g_p - s);
    if (l >= 32) { g_err = 1; return 0; }
    char buf[32];
    memcpy(buf, s, l);
    buf[l] = '\0';
    out->num = strtoll(buf, NULL, 10);
    return 1;
}

static int gval(gm *out) {
    gskip();
    if (g_p >= g_end) { g_err = 1; return 0; }
    out->t = GM_NULL;
    out->b = 0;
    out->num = 0;
    out->str = NULL;
    out->el = NULL;
    out->ne = 0;
    out->k = NULL;
    out->v = NULL;
    out->nd = 0;
    char c = *g_p;
    if (c == 'n') {
        if ((size_t)(g_end - g_p) >= 4 && memcmp(g_p, "null", 4) == 0) { g_p += 4; return 1; }
        g_err = 1; return 0;
    }
    if (c == 't') {
        if ((size_t)(g_end - g_p) >= 4 && memcmp(g_p, "true", 4) == 0) { g_p += 4; out->t = GM_BOOL; out->b = 1; return 1; }
        g_err = 1; return 0;
    }
    if (c == 'f') {
        if ((size_t)(g_end - g_p) >= 5 && memcmp(g_p, "false", 5) == 0) { g_p += 5; out->t = GM_BOOL; out->b = 0; return 1; }
        g_err = 1; return 0;
    }
    if (c == '"') {
        char *s = gstr();
        if (g_err) return 0;
        out->t = GM_STR;
        out->str = s;
        return 1;
    }
    if (c == '{') {
        g_p++;
        size_t cap = 4;
        out->k = calloc(cap, sizeof(char *));
        out->v = calloc(cap, sizeof(gm *));
        if (!out->k || !out->v) { g_err = 1; return 0; }
        out->t = GM_OBJ;
        gskip();
        if (g_p < g_end && *g_p == '}') { g_p++; return 1; }
        for (;;) {
            gskip();
            char *key = gstr();
            if (g_err) return 0;
            gskip();
            if (g_p >= g_end || *g_p != ':') { free(key); g_err = 1; return 0; }
            g_p++;
            gm *child = calloc(1, sizeof(gm));
            if (!child) { free(key); g_err = 1; return 0; }
            if (!gval(child)) { free(key); free(child); g_err = 1; return 0; }
            if (out->nd == cap) {
                size_t ncap = cap * 2;
                char **nk = realloc(out->k, ncap * sizeof(char *));
                if (!nk) { free(key); free(child); g_err = 1; return 0; }
                gm **nv = realloc(out->v, ncap * sizeof(gm *));
                if (!nv) { free(nk); free(key); free(child); g_err = 1; return 0; }
                out->k = nk;
                out->v = nv;
                cap = ncap;
            }
            out->k[out->nd] = key;
            out->v[out->nd] = child;
            out->nd++;
            gskip();
            if (g_p >= g_end) { g_err = 1; return 0; }
            if (*g_p == ',') { g_p++; continue; }
            if (*g_p == '}') { g_p++; return 1; }
            g_err = 1; return 0;
        }
    }
    if (c == '[') {
        g_p++;
        size_t cap = 4;
        out->el = calloc(cap, sizeof(gm *));
        if (!out->el) { g_err = 1; return 0; }
        out->t = GM_ARR;
        gskip();
        if (g_p < g_end && *g_p == ']') { g_p++; return 1; }
        for (;;) {
            gm *child = calloc(1, sizeof(gm));
            if (!child) { g_err = 1; return 0; }
            if (!gval(child)) { free(child); g_err = 1; return 0; }
            if (out->ne == cap) {
                size_t ncap = cap * 2;
                gm **ne2 = realloc(out->el, ncap * sizeof(gm *));
                if (!ne2) { free(child); g_err = 1; return 0; }
                out->el = ne2;
                cap = ncap;
            }
            out->el[out->ne++] = child;
            gskip();
            if (g_p >= g_end) { g_err = 1; return 0; }
            if (*g_p == ',') { g_p++; continue; }
            if (*g_p == ']') { g_p++; return 1; }
            g_err = 1; return 0;
        }
    }
    if (c == '-' || (c >= '0' && c <= '9')) {
        out->t = GM_NUM;
        return gnum(out);
    }
    g_err = 1;
    return 0;
}

static void gfree_rec(gm *v) {
    if (!v) return;
    free(v->str);
    for (size_t i = 0; i < v->ne; i++) gfree_rec(v->el[i]);
    for (size_t i = 0; i < v->nd; i++) {
        free(v->k[i]);
        gfree_rec(v->v[i]);
    }
    free(v->el);
    free(v->k);
    free(v->v);
}

static int gm_parse(const char *s, size_t n, gm *out) {
    g_p = s;
    g_end = s + n;
    g_err = 0;
    memset(out, 0, sizeof(*out));
    if (!gval(out)) return -1;
    gskip();
    if (g_p != g_end) return -1;
    return 0;
}

static void gm_free(gm *v) { gfree_rec(v); }

static const gm *gm_get(const gm *o, const char *key) {
    if (!o || o->t != GM_OBJ) return NULL;
    for (size_t i = 0; i < o->nd; i++)
        if (strcmp(o->k[i], key) == 0) return o->v[i];
    return NULL;
}

static int gm_num(const gm *v, int64_t *out) {
    if (!v || v->t != GM_NUM) return -1;
    *out = v->num;
    return 0;
}

static int gm_str(const gm *v, const char **out) {
    if (!v || v->t != GM_STR) return -1;
    *out = v->str;
    return 0;
}

static int gm_bool(const gm *v, int *out) {
    if (!v || v->t != GM_BOOL) return -1;
    *out = v->b;
    return 0;
}

#endif
