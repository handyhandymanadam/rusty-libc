#ifndef _NETDB_H
#define _NETDB_H 1
#include <stddef.h>
#include <stdint.h>
#include <netinet/in.h>
#include <bits/types/struct_timespec.h>
#include <bits/types/struct_sigevent.h>

#define _PATH_HEQUIV "/etc/hosts.equiv"
#define _PATH_HOSTS "/etc/hosts"
#define _PATH_NETWORKS "/etc/networks"
#define _PATH_NSSWITCH_CONF "/etc/nsswitch.conf"
#define _PATH_PROTOCOLS "/etc/protocols"
#define _PATH_SERVICES "/etc/services"

#define h_errno (*__h_errno_location ())

#define AI_ADDRCONFIG 32
#define AI_ALL 16
#define AI_CANONIDN 128
#define AI_CANONNAME 2
#define AI_IDN 64
#define AI_NUMERICHOST 4
#define AI_NUMERICSERV 1024
#define AI_PASSIVE 1
#define AI_V4MAPPED 8
#define EAI_ADDRFAMILY -9
#define EAI_AGAIN -3
#define EAI_ALLDONE -103
#define EAI_BADFLAGS -1
#define EAI_CANCELED -101
#define EAI_FAIL -4
#define EAI_FAMILY -6
#define EAI_IDN_ENCODE -105
#define EAI_INPROGRESS -100
#define EAI_INTR -104
#define EAI_MEMORY -10
#define EAI_NODATA -5
#define EAI_NONAME -2
#define EAI_NOTCANCELED -102
#define EAI_OVERFLOW -12
#define EAI_SERVICE -8
#define EAI_SOCKTYPE -7
#define EAI_SYSTEM -11
#define GAI_NOWAIT 1
#define GAI_WAIT 0
#define HOST_NOT_FOUND 1
#define NETDB_INTERNAL -1
#define NETDB_SUCCESS 0
#define NI_DGRAM 16
#define NI_IDN 32
#define NI_MAXHOST 1025
#define NI_MAXSERV 32
#define NI_NAMEREQD 8
#define NI_NOFQDN 4
#define NI_NUMERICHOST 1
#define NI_NUMERICSERV 2
#define NO_ADDRESS 4
#define NO_DATA 4
#define NO_RECOVERY 3
#define TRY_AGAIN 2

struct hostent {
  char *h_name;
  char **h_aliases;
  int h_addrtype;
  int h_length;
  char **h_addr_list;
};
#define h_addr h_addr_list[0]

struct servent {
  char *s_name;
  char **s_aliases;
  int s_port;
  char *s_proto;
};

struct protoent {
  char *p_name;
  char **p_aliases;
  int p_proto;
};

struct netent {
  char *n_name;
  char **n_aliases;
  int n_addrtype;
  uint32_t n_net;
};

struct rpcent {
  char *r_name;
  char **r_aliases;
  int r_number;
};

struct addrinfo {
  int ai_flags;
  int ai_family;
  int ai_socktype;
  int ai_protocol;
  socklen_t ai_addrlen;
  struct sockaddr *ai_addr;
  char *ai_canonname;
  struct addrinfo *ai_next;
};

struct gaicb {
  const char *ar_name;
  const char *ar_service;
  const struct addrinfo *ar_request;
  struct addrinfo *ar_result;
  int __return;
  int __glibc_reserved[5];
};

#include <bits/rlibc-net-netdb.h>
#endif
