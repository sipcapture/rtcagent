/*

LINK - http://github.com/sipcapture/rtcagent

Copyright (C) 2023 QXIP B.V.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU Affero General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/


#include "rtcagent.h"

#define _SYS_SOCKET_H 1
#define IP4_MAX_STR_SIZE 15
#define IP6_MAX_STR_SIZE 45
#define IP_ADDR_MAX_STR_SIZE 6 /* ip62ascii +  \0*/
#define SS_MAXSIZE 128         /* Implementation specific max size */
#define MAX_DATA_SIZE_SIP 1024*4

typedef unsigned short sa_family_t;

typedef struct _str
{
    char *s;
    int len;
} str;

struct sockaddr_storage
{
    union
    {
        struct
        {
            sa_family_t ss_family; /* address family */
            /* Following field(s) are implementation specific */
            char __data[SS_MAXSIZE - sizeof(unsigned short)];
            /* space to achieve desired size, */
            /* _SS_MAXSIZE value minus size of ss_family */
        };
        void *__align; /* implementation specific desired alignment */
    };
};

typedef struct ip_addr
{
    unsigned int af;  /* address family: AF_INET6 or AF_INET */
    unsigned int len; /* address len, 16 or 4 */

    /* 64 bits aligned address */
    union
    {
        unsigned long addrl[16 / sizeof(long)]; /* long format*/
        unsigned int addr32[4];
        unsigned short addr16[8];
        unsigned char addr[16];
    } u;
} ip_addr_t;

typedef struct advertise_info
{
    str name;               /* name - eg.: foo.bar or 10.0.0.1 */
    unsigned short port_no; /* port number */
    short port_pad;         /* padding field */
    str port_no_str;        /* port number converted to string -- optimization*/
    str address_str;        /*ip address converted to string -- optimization*/
    struct ip_addr address; /* ip address */
    str sock_str;           /* Socket proto, ip, and port as string */
} advertise_info_t;

typedef struct snd_flags
{
    unsigned short f;          /* snd flags */
    unsigned short blst_imask; /* blocklist ignore mask */
} snd_flags_t;

typedef enum si_flags
{
    SI_NONE = 0,
    SI_IS_IP = (1 << 0),
    SI_IS_LO = (1 << 1),
    SI_IS_MCAST = (1 << 2),
    SI_IS_ANY = (1 << 3),
    SI_IS_MHOMED = (1 << 4),
    SI_IS_VIRTUAL = (1 << 5),
} si_flags_t;

typedef union sockaddr_union
{
    struct sockaddr s;
    struct sockaddr_in sin;
    struct sockaddr_in6 sin6;
    struct sockaddr_storage sas;
} sr_sockaddr_union_t;

typedef struct socket_info
{
    int socket;
    int gindex;             /* global index in the lists of all sockets */
    str name;               /* name - eg.: foo.bar or 10.0.0.1 */
    struct ip_addr address; /* ip address */
    str address_str;        /*ip address converted to string -- optimization*/
    str port_no_str;        /* port number converted to string -- optimization*/
    enum si_flags flags;    /* SI_IS_IP | SI_IS_LO | SI_IS_MCAST */
    union sockaddr_union su;
    struct socket_info *next;
    struct socket_info *prev;
    unsigned short port_no;          /* port number */
    char proto;                      /* tcp or udp*/
    char proto_pad0;                 /* padding field */
    short proto_pad1;                /* padding field */
    str sock_str;                    /* Socket proto, ip, and port as string */
    struct addr_info *addr_info_lst; /* extra addresses (e.g. SCTP mh) */
    int workers;                     /* number of worker processes for this socket */
    int workers_tcpidx;              /* index of workers in tcp children array */
    str sockname;                    /* socket name given in config listen value */
    struct advertise_info useinfo;   /* details to be used in SIP msg */
#ifdef USE_MCAST
    str mcast; /* name of interface that should join multicast group*/
#endif         /* USE_MCAST */
} socket_info_t;

typedef struct dest_info
{
    struct socket_info *send_sock;
    union sockaddr_union to;
    int id; /* tcp stores the connection id here */
    snd_flags_t send_flags;
    char proto;
#ifdef USE_COMP
    char proto_pad0; /* padding field */
    short comp;
#else
    char proto_pad0;  /* padding field */
    short proto_pad1; /* padding field */
#endif
} dest_info_t;

/* inits an ip_addr pointer from a sockaddr_union ip address */
static inline void su2ip_addr(struct ip_addr *ip, const union sockaddr_union *su)
{
    switch (su->s.sa_family)
    {
    case AF_INET:
        ip->af = AF_INET;
        ip->len = 4;
        __builtin_memcpy(ip->u.addr, &su->sin.sin_addr, 4);
        break;
    case AF_INET6:
        ip->af = AF_INET6;
        ip->len = 16;
        __builtin_memcpy(ip->u.addr, &su->sin6.sin6_addr, 16);
        break;
    default:
        __builtin_memset(ip, 0, sizeof(ip_addr_t));
    }
}
