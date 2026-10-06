#ifndef NTX_SOCK_H
#define NTX_SOCK_H

#include "ntx_addr.h"

#include <stddef.h>
#include <stdint.h>

int ntx_sock_tcp4(void);
int ntx_sock_tcp6(void);
int ntx_sock_udp4(void);
/* AF_INET6 UDP + SO_REUSEADDR + IPV6_V6ONLY=1 (before bind). -1 on failure. */
int ntx_sock_udp6(void);
uint16_t ntx_sock_bind0(int fd);
/* Bind listen socket to first free port in [lo,hi] (inclusive). If lo==hi==0 or
 * every port fails, falls back to bind0 (ephemeral). Returns bound port or 0. */
uint16_t ntx_sock_bind_range(int fd, uint16_t lo, uint16_t hi);
/* Bind AF_INET6 listen socket to [::]:port (port 0 = ephemeral),
 * IPV6_V6ONLY=1 set before bind. Returns actual port (host order) or 0. */
uint16_t ntx_sock_bind6(int fd, uint16_t port);
/* Bind AF_INET6 listen socket to first free port in [lo,hi] (inclusive).
 * If lo==hi==0 or every port fails, falls back to bind6 (ephemeral).
 * Returns bound port or 0. */
uint16_t ntx_sock_bind_range6(int fd, uint16_t lo, uint16_t hi);
uint16_t ntx_sock_local_port(int fd);
uint16_t ntx_sock_local_port6(int fd);
int ntx_sock_listen(int fd, int backlog);
int ntx_sock_accept4(int listen_fd);
int ntx_sock_connect4(int fd, uint32_t ip_net, uint16_t port);
/* port in host order; v4 -> sockaddr_in, v6 -> sockaddr_in6; unspecified
 * (zero) address -> -1. Non-blocking connect: 0 = started (EINPROGRESS ok). */
int ntx_sock_connect_addr(int fd, const ntx_addr *addr, uint16_t port);
/* Resolve host to ntx_addr: dotted-quad -> v4 literal; IPv6 literal
 * ("::1" or "[::1]") -> v6 literal; else DoH AAAA (first record);
 * else DoH A (first record); else -1. No getaddrinfo. */
int ntx_sock_resolve(const char *host, ntx_addr *out);
/* Compat wrapper: ntx_sock_resolve requiring family==v4 and non-zero. */
int ntx_sock_resolve4(const char *host, uint32_t *ip_out);
int ntx_sock_tcp_connect_host(const char *host, uint16_t port);

/* Implemented in ntx_sock.c: ntx_sock_parse_host_port */
int ntx_sock_parse_host_port(const char *spec, char *hostbuf, size_t hcap,
                             const char **host_out, uint16_t *port_out);
#endif
