#include "ntx_http_url.h"
#include <string.h>

static int host_bad_char(char c) {
  unsigned char u = (unsigned char)c;
  /* '@' and '\\' are userinfo / authority tricks (http://good@evil/), which we do not support */
  return u < 0x20 || u == 0x7f || c == ' ' || c == '/' || c == '@' || c == '\\';
}

/* The rest of the URL goes verbatim into the request line.  Any control byte or space there
 * (CR/LF above all) would let a webseed / tracker / magnet URL inject headers or a second request. */
static int path_bad(const char *p) {
  for (; *p; p++) {
    unsigned char u = (unsigned char)*p;
    if (u <= 0x20 || u == 0x7f) return 1;
  }
  return 0;
}

int ntx_http_url_parse(const char *url, ntx_http_url_parts *out) {
  if (!url || !out) return -1;

  const char *p;
  int is_tls;
  uint16_t def_port;

  if (strncmp(url, "http://", 7) == 0) {
    is_tls = 0;
    def_port = 80;
    p = url + 7;
  } else if (strncmp(url, "https://", 8) == 0) {
    is_tls = 1;
    def_port = 443;
    p = url + 8;
  } else {
    return -1;
  }

  char host[256];
  size_t hlen;

  if (*p == '[') {
    const char *close = strchr(p, ']');
    if (!close) return -1;
    hlen = (size_t)(close - p - 1);
    if (hlen < 1 || hlen > 255) return -1;
    for (size_t i = 0; i < hlen; i++) {
      if (host_bad_char(p[1 + i])) return -1;
    }
    memcpy(host, p + 1, hlen);
    host[hlen] = '\0';
    p = close + 1;
  } else {
    const char *end = p;
    while (*end && *end != ':' && *end != '/' && *end != '?') end++;
    hlen = (size_t)(end - p);
    if (hlen < 1 || hlen > 255) return -1;
    for (size_t i = 0; i < hlen; i++) {
      if (host_bad_char(p[i])) return -1;
    }
    memcpy(host, p, hlen);
    host[hlen] = '\0';
    p = end;
  }

  uint16_t port = def_port;
  if (*p == ':') {
    p++;
    if (*p < '0' || *p > '9') return -1;
    long v = 0;
    while (*p >= '0' && *p <= '9') {
      v = v * 10 + (long)(*p - '0');
      if (v > 65535) return -1;
      p++;
    }
    port = (uint16_t)v;
  }

  if (path_bad(p)) return -1;
  if (*p == '/' || *p == '?') {
    out->path = p;
  } else if (*p != '\0') {
    return -1; /* e.g. "http://host:80x/": junk after the authority */
  } else {
    static const char kSlash[] = "/";
    out->path = kSlash;
  }

  memcpy(out->host, host, hlen + 1);
  out->port = port;
  out->is_tls = is_tls;
  return 0;
}
