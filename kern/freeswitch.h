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
#define MAX_DATA_SIZE_SIP 1024 * 4
#define BUFFER_SIZE 512


// freeswitch ============================= BEGIN! ===========================================

//#define DOCUMENTATION_ONLY 1
//#define SU_HAVE_SOCKADDR_SA_LEN 1
#define SUB_N 31
#define SIZEBITS (sizeof(unsigned) * 8 - 1)
typedef size_t usize_t;
typedef size_t isize_t;
typedef ssize_t issize_t;
#define SU_HOME_T struct su_home_s
typedef SU_HOME_T su_home_t;
typedef struct su_block_s su_block_t;
typedef struct su_alock su_alock_t;
typedef struct su_home_stat_t su_home_stat_t;

typedef struct su_iovec_s msg_iovec_t;

typedef size_t su_ioveclen_t;

 
typedef struct {
  char const *tpn_proto;	/**< Protocol name ("udp", "tcp", etc.) */
  char const *tpn_canon;	/**< Node DNS name (if known). */
  char const *tpn_host;		/**< Node address in textual format */
  char const *tpn_port;		/**< Port number in textual format. */
  char const *tpn_comp;		/**< Compression algorithm (NULL if none) */
  char const *tpn_ident;	/**< Transport identifier (NULL if none) */
} tp_name_t;

typedef struct su_iovec_s {
  void  *siv_base;		/**< Pointer to buffer. */
  su_ioveclen_t siv_len;		/**< Size of buffer.  */
} su_iovec_t;

typedef struct
{
    unsigned sua_size : SIZEBITS; /**< Size of the block */
    unsigned sua_home : 1;        /**< Is this another home? */
    unsigned : 0;
    void *sua_data; /**< Data pointer */
} su_alloc_t;

struct su_block_s
{
    su_home_t *sub_parent;          /**< Parent home */
    char *sub_preload;              /**< Preload area */
    su_home_stat_t *sub_stats;      /**< Statistics.. */
    void (*sub_destructor)(void *); /**< Destructor function */
    size_t sub_ref;                 /**< Reference count */
#define REF_MAX SIZE_MAX
    size_t sub_used; /**< Number of blocks allocated */
    size_t sub_n;    /**< Size of hash table  */

    unsigned sub_prsize : 16;  /**< Preload size */
    unsigned sub_prused : 16;  /**< Used from preload */
    unsigned sub_hauto : 1;    /**< "Home" is not from malloc */
    unsigned sub_auto : 1;     /**< struct su_block_s is not from malloc */
    unsigned sub_preauto : 1;  /**< Preload is not from malloc */
    unsigned sub_auto_all : 1; /**< Everything is from stack! */
    unsigned : 0;

    su_alloc_t sub_nodes[SUB_N]; /**< Pointers to data/lower blocks */
};

struct su_home_s
{
    int suh_size;
    su_block_t *suh_blocks;
    su_alock_t *suh_lock;
};

/** Message class. */
typedef struct msg_mclass_s msg_mclass_t;

/** Header class. */
typedef struct msg_hclass_s const msg_hclass_t;

/** Header reference. */
typedef struct msg_href_s msg_href_t;

/** Message object. */
typedef struct msg_s msg_t;

#ifndef MSG_TIME_T_DEFINED
#define MSG_TIME_T_DEFINED
/** Time in seconds since epoch (1900-Jan-01 00:00:00). */
typedef unsigned long msg_time_t;
#endif

#ifndef MSG_TIME_MAX
/** Latest time that can be expressed with msg_time_t. @HIDE */
#define MSG_TIME_MAX ((msg_time_t)ULONG_MAX)
#endif

#ifndef MSG_PUB_T
#ifdef MSG_OBJ_T
#define MSG_PUB_T MSG_OBJ_T
#else
#define MSG_PUB_T struct msg_pub_s
#endif
#endif

/**Public protocol-specific message structure for accessing the message.
 *
 * This type can be either #sip_t, #http_t, or #msg_multipart_t, depending
 * on the message. The base structure used by msg module is defined in
 * struct #msg_pub_s.
 */
typedef MSG_PUB_T msg_pub_t;

#ifndef MSG_HDR_T
#define MSG_HDR_T union msg_header_u
#endif
/** Any protocol-specific header object */
typedef MSG_HDR_T msg_header_t;

typedef struct msg_common_s msg_common_t;

typedef struct msg_separator_s msg_separator_t;
typedef struct msg_payload_s msg_payload_t;
typedef struct msg_unknown_s msg_unknown_t;
typedef struct msg_error_s msg_error_t;

typedef msg_common_t msg_frg_t;

typedef char const *msg_param_t;
typedef struct msg_numeric_s msg_numeric_t;
typedef struct msg_generic_s msg_generic_t;
typedef struct msg_list_s msg_list_t;
typedef struct msg_auth_s msg_auth_t;
typedef struct msg_auth_info_s msg_auth_info_t;

#define MSG_HEADER_N 16377

/** Common part of the header objects (or message fragments).
 *
 * This structure is also known as #msg_common_t or #sip_common_t.
 */
struct msg_common_s
{
    msg_header_t *h_succ;  /**< Pointer to succeeding fragment. */
    msg_header_t **h_prev; /**< Pointer to preceeding fragment. */
    msg_hclass_t *h_class; /**< Header class. */
    void const *h_data;    /**< Fragment data */
    usize_t h_len;         /**< Fragment length (including CRLF) */
};

/** Message object, common view */
struct msg_pub_s
{
    msg_common_t msg_common[1]; /**< Recursive */
    msg_pub_t *msg_next;
    void *msg_user;
    unsigned msg_size;
    unsigned msg_flags;
    msg_error_t *msg_error;
    msg_header_t *msg_request;
    msg_header_t *msg_status;
    msg_header_t *msg_headers[MSG_HEADER_N];
};

#define msg_ident msg_common->h_class

/** Numeric header.
 *
 * A numeric header has value range of a 32-bit, 0..4294967295. The @a
 * x_value field is unsigned long, however.
 */
struct msg_numeric_s
{
    msg_common_t x_common[1]; /**< Common fragment info */
    msg_numeric_t *x_next;    /**< Link to next header */
    unsigned long x_value;    /**< Numeric header value */
};

/** Generic header.
 *
 * A generic header does not have any internal structure. Its value is
 * represented as a string.
 */
struct msg_generic_s
{
    msg_common_t g_common[1]; /**< Common fragment info */
    msg_generic_t *g_next;    /**< Link to next header */
    char const *g_string;     /**< Header value */
};

/** List header.
 *
 * A list header consists of comma-separated list of tokens.
 */
struct msg_list_s
{
    msg_common_t k_common[1]; /**< Common fragment info */
    msg_list_t *k_next;       /**< Link to next header */
    msg_param_t *k_items;     /**< List of items */
};

/** Authentication header.
 *
 * An authentication header has authentication scheme name and
 * comma-separated list of parameters as its value.
 */
struct msg_auth_s
{
    msg_common_t au_common[1];    /**< Common fragment info */
    msg_auth_t *au_next;          /**< Link to next header */
    char const *au_scheme;        /**< Auth-scheme like Basic or Digest */
    msg_param_t const *au_params; /**< Comma-separated parameters */
};

/**Authentication-Info header
 *
 * An Authentication-Info header has comma-separated list of parameters as its value.
 */
struct msg_auth_info_s
{
    msg_common_t ai_common[1];    /**< Common fragment info */
    msg_error_t *ai_next;         /**< Dummy link to next */
    msg_param_t const *ai_params; /**< List of ainfo */
};

/** Unknown header. */
struct msg_unknown_s
{
    msg_common_t un_common[1]; /**< Common fragment info */
    msg_unknown_t *un_next;    /**< Link to next unknown header */
    char const *un_name;       /**< Header name */
    char const *un_value;      /**< Header field value */
};

/** Erroneus header. */
struct msg_error_s
{
    msg_common_t er_common[1]; /**< Common fragment info */
    msg_error_t *er_next;      /**< Link to next header */
    char const *er_name;       /**< Name of bad header (if any). */
};

/** Separator. */
struct msg_separator_s
{
    msg_common_t sep_common[1]; /**< Common fragment info */
    msg_error_t *sep_next;      /**< Dummy link to next header */
    char sep_data[4];           /**< NUL-terminated separator */
};

/** Message payload. */
struct msg_payload_s
{
    msg_common_t pl_common[1]; /**< Common fragment info */
    msg_payload_t *pl_next;    /**< Next payload chunk */
    char *pl_data;             /**< Data - may contain NUL */
    usize_t pl_len;            /**< Length of message payload */
};

/** Any header. */
union msg_header_u
{
    msg_common_t sh_common[1]; /**< Common fragment info */
    struct
    {
        msg_common_t shn_common;
        msg_header_t *shn_next;
    } sh_header_next[1];
#define sh_next sh_header_next->shn_next
#define sh_class sh_common->h_class
#define sh_succ sh_common->h_succ
#define sh_prev sh_common->h_prev
#define sh_data sh_common->h_data
#define sh_len sh_common->h_len

    msg_generic_t sh_generic[1];
    msg_numeric_t sh_numeric[1];
    msg_list_t sh_list[1];
    msg_auth_t sh_auth[1];
    msg_separator_t sh_separator[1];
    msg_payload_t sh_payload[1];
    msg_unknown_t sh_unknown[1];
    msg_error_t sh_error[1];
};

/* ====================================================================== */

/**Define how to handle existing headers
 * when a new header is added to a message.
 */
typedef enum
{
    msg_kind_single,            /**< Only one header is allowed */
    msg_kind_append,            /**< New header is appended */
    msg_kind_list,              /**< A token list header,
                                 * new header is combined with old one. */
    msg_kind_apndlist,          /**< A complex list header. */
    msg_kind_prepend,           /**< New header is prepended */
    msg_kind_non_compact_append /**< Non-compact New header is appended */
} msg_header_kind_t;

#define MSG_KIND_IS_COMPACT(f) (f != msg_kind_non_compact_append)

struct su_home_s;

typedef issize_t msg_parse_f(struct su_home_s *, msg_header_t *, char *, isize_t);
typedef issize_t msg_print_f(char buf[], isize_t bufsiz, msg_header_t const *, int flags);
typedef char *msg_dup_f(msg_header_t *dst, msg_header_t const *src,
                        char *buf, isize_t bufsiz);
typedef isize_t msg_xtra_f(msg_header_t const *h, isize_t offset);

typedef int msg_update_f(msg_common_t *, char const *name, isize_t namelen,
                         char const *value);

/** Factory object for a header.
 *
 * The #msg_hclass_t object, "header class", defines how a header is
 * handled. It has parsing and printing functions, functions used to copy
 * header objects, header name and other information used when parsing,
 * printing, removing, adding and replacing headers within a message.
 */
struct msg_hclass_s
{
    /* XXX size of header class missing. Someone has saved bits in wrong place. */
    int hc_hash;              /**< Header name hash or ID */
    msg_parse_f *hc_parse;    /**< Parse header. */
    msg_print_f *hc_print;    /**< Print header. */
    msg_xtra_f *hc_dxtra;     /**< Calculate extra size for dup */
    msg_dup_f *hc_dup_one;    /**< Duplicate one header. */
    msg_update_f *hc_update;  /**< Update parameter(s) */
    char const *hc_name;      /**< Full name. */
    short hc_len;             /**< Length of hc_name. */
    char hc_short[2];         /**< Short name, if any. */
    unsigned char hc_size;    /**< Size of header structure. */
    unsigned char hc_params;  /**< Offset of parameter list */
    unsigned hc_kind : 3;     /**< Kind of header (#msg_header_kind_t):
                               * single, append, list, apndlist, prepend. */
    unsigned hc_critical : 1; /**< True if header is critical */
    unsigned /*pad*/ : 0;
};

#define HC_LEN_MAX SHRT_MAX

typedef struct msg_buffer_s msg_buffer_t;
typedef struct addrinfo su_addrinfo_t;
typedef union su_sockaddr_u su_sockaddr_t;

union su_sockaddr_u
{
#ifdef DOCUMENTATION_ONLY
    uint8_t su_len;    /**< Length of structure */
    uint8_t su_family; /**< Address family. */
    uint16_t su_port;  /**< Port number. */
#else
    short su_dummy;   /**< Dummy member to initialize */
#if SU_HAVE_SOCKADDR_SA_LEN
#define su_len su_sa.sa_len
#else
#define su_len su_array[0]
#endif
#define su_family su_sa.sa_family
#define su_port su_sin.sin_port
#endif

    char su_array[32];         /**< Presented as chars */
    uint16_t su_array16[16];   /**< Presented as 16-bit ints */
    uint32_t su_array32[8];    /**< Presented as 32-bit ints */
    struct sockaddr su_sa;     /**< Address in struct sockaddr format */
    struct sockaddr_in su_sin; /**< Address in IPv4 format */
#if SU_HAVE_IN6
    struct sockaddr_in6 su_sin6; /**< Address in IPv6 format */
#endif
#ifdef DOCUMENTATION_ONLY
    uint32_t su_scope_id; /**< Scope ID. */
#else
#define su_scope_id su_array32[6]
#endif
};

struct addrinfo
{
    int ai_flags;             /* AI_PASSIVE, AI_CANONNAME */
    int ai_family;            /* PF_xxx */
    int ai_socktype;          /* SOCK_xxx */
    int ai_protocol;          /* 0 or IPPROTO_xxx for IPv4 and IPv6 */
    size_t ai_addrlen;        /* length of ai_addr */
    char *ai_canonname;       /* canonical name for hostname */
    struct sockaddr *ai_addr; /* binary address */
    struct addrinfo *ai_next; /* next structure in linked list */
};

struct msg_s
{
    su_home_t m_home[1]; /**< Memory home */

    msg_mclass_t const *m_class; /**< Message class */
    int m_oflags;                /**< Original flags */

    msg_pub_t *m_object; /**< Public view to parsed message */

    size_t m_maxsize; /**< Maximum size */
    size_t m_size;    /**< Total size of fragments */

    msg_header_t *m_chain; /**< Fragment chain */
    msg_header_t **m_tail; /**< Tail of fragment chain */

    msg_payload_t *m_chunk; /**< Incomplete payload fragment */

    /* Parsing/printing buffer */
    struct msg_mbuffer_s
    {
        char *mb_data;       /**< Pointer to data */
        usize_t mb_size;     /**< Size of buffer */
        usize_t mb_used;     /**< Used data */
        usize_t mb_commit;   /**< Data committed to msg */
        unsigned mb_eos : 1; /**< End-of-stream flag */
        unsigned : 0;
    } m_buffer[1];

    msg_buffer_t *m_stream; /**< User-provided buffers */
    size_t m_ssize;         /**< Stream size */

    unsigned short m_extract_err; /**< Bitmask of erroneous headers */
    /* Internal flags */
    unsigned m_set_buffer : 1; /**< Buffer has been set */
    unsigned m_streaming : 1;  /**< Use streaming with message */
    unsigned m_prepared : 1;   /**< Prepared/not */
    unsigned : 0;

    msg_t *m_next; /**< Next message */

    msg_t *m_parent; /**< Reference to a parent message */
    int m_refs;      /**< Number of references to this message */

    su_addrinfo_t m_addrinfo; /**< Message addressing info (protocol) */
    su_sockaddr_t m_addr[1];  /**< Message address */

    int m_errno; /**< Errno */
};

struct tport_s;
typedef struct su_strlst_s su_strlst_t;
typedef int su_socket_t;


#ifndef TPORT_T
#define TPORT_T struct tport_s
typedef TPORT_T tport_t;
#endif
#ifndef TP_MAGIC_T
/** Type of transport-protocol-specific context.  @sa @ref tp_magic */
#define TP_MAGIC_T struct tp_magic_s
#endif
typedef struct tport_master tport_master_t;
typedef struct tport_pending_s tport_pending_t;
typedef struct tport_primary tport_primary_t;
typedef struct tport_vtable tport_vtable_t;
typedef TP_MAGIC_T tp_magic_t;
/** Timer object type. */
typedef struct su_timer_s su_timer_t;

struct su_time_s {
  unsigned long tv_sec;		/**< Seconds */
  unsigned long tv_usec;	/**< Microseconds  */
};
/** Time in seconds and microsecondcs. */
typedef struct su_time_s su_time_t;
#ifndef TPORT_COMPRESSOR
#define TPORT_COMPRESSOR struct tport_compressor
#endif

typedef TPORT_COMPRESSOR tport_compressor_t;
typedef struct {
  unsigned tpp_mtu;		/**< Maximum packet size */
  unsigned tpp_idle;		/**< Allowed connection idle time. */
  unsigned tpp_timeout;		/**< Allowed idle time for message. */
  unsigned tpp_socket_keepalive;/**< Socket keepalive interval */
  unsigned tpp_keepalive;	/**< Keepalive PING interval */
  unsigned tpp_pingpong;	/**< PONG-to-PING interval */

  unsigned tpp_sigcomp_lifetime;  /**< SigComp compartment lifetime  */
  unsigned tpp_thrpsize;	/**< Size of thread pool */

  unsigned tpp_thrprqsize;	/**< Length of per-thread recv queue */
  unsigned tpp_qsize;		/**< Size of queue */

  unsigned tpp_drop;		/**< Packet drop probablity */
  int      tpp_tos;         	/**< IP TOS */

  unsigned tpp_conn_orient:1;   /**< Connection-orienteded */
  unsigned tpp_sdwn_error:1;	/**< If true, shutdown is error. */
  unsigned tpp_stun_server:1;	/**< If true, use stun server */
  unsigned tpp_pong2ping:1;	/**< If true, respond with pong to ping */

  unsigned :0;

} tport_params_t;


/** @internal Transport object.
 *
 * A transport object can be used in three roles, to represent transport
 * list (aka master transport), to represent available transports (aka
 * primary transport) and to represent actual transport connections (aka
 * secondary transport).
 */
struct tport_s {
  su_home_t           tp_home[1];       /**< Memory home */

  ssize_t             tp_refs;		/**< Number of references to tport */

  unsigned            tp_black:1;       /**< Used by red-black-tree */

  unsigned            tp_accepted:1;    /**< Originally server? */
  unsigned            tp_conn_orient:1;	/**< Is connection-oriented */
  unsigned            tp_has_connection:1; /**< Has real connection */
  unsigned            tp_reusable:1;    /**< Can this connection be reused */
  unsigned            tp_closed : 1;
  /**< This transport is closed.
   *
   * A closed transport is inserted into pri_closed list.
   */

  /** Remote end has sent FIN (2) or we should not just read */
  unsigned            tp_recv_close:2;
  /** We will send FIN (1) or have sent FIN (2) */
  unsigned            tp_send_close:2;
  unsigned            tp_has_keepalive:1;
  unsigned            tp_has_stun_server:1;
  unsigned            tp_trunc:1;
  unsigned            tp_is_connected:1; /**< Connection is established */
  unsigned            tp_verified:1;     /**< Certificate Chain was verified */
  unsigned            tp_pre_framed:1;   /** Data is pre-framed **/
  unsigned:0;

  tport_t *tp_left, *tp_right, *tp_dad; /**< Links in tport tree */

  tport_master_t     *tp_master;        /**< Master transport */
  tport_primary_t    *tp_pri;           /**< Primary transport */

  tport_params_t     *tp_params;        /**< Transport parameters */

  tp_magic_t         *tp_magic; 	/**< Context provided by consumer */

  su_timer_t         *tp_timer;	        /**< Timer object */

  su_time_t           tp_ktime;	        /**< Keepalive timer updated */
  su_time_t           tp_ptime;	        /**< Ping sent */

  tp_name_t           tp_name[1];	/**< Transport name.
					 *
					 * This is either our name (if primary)
					 * or peer name (if secondary).
					 */

  su_strlst_t        *tp_subjects;      /**< Transport Subjects.
                                         *
                                         * Subject Name(s) provided by the peer
					 * in a TLS connection (if secondary).
					 * or matched against incoming 
					 * connections (if primary).
                                         */

#define tp_protoname tp_name->tpn_proto
#define tp_canon     tp_name->tpn_canon
#define tp_host      tp_name->tpn_host
#define tp_port      tp_name->tpn_port
#define tp_ident     tp_name->tpn_ident

  su_socket_t  	      tp_socket;	/**< Socket of this tport*/
  int                 tp_index;		/**< Root registration index */
  int                 tp_events;        /**< Subscribed events */

  su_addrinfo_t       tp_addrinfo[1];   /**< Peer/own address info */
  su_sockaddr_t       tp_addr[1];	/**< Peer/own address */
#define tp_addrlen tp_addrinfo->ai_addrlen

  /* ==== Receive queue ================================================== */

  msg_t   	     *tp_msg;		/**< Message being received */
  msg_t const        *tp_rlogged;       /**< Last logged when receiving */
  su_time_t           tp_rtime;	        /**< Last time received data */
  unsigned short      tp_ping;	        /**< Whitespace ping being received */

  /* ==== Pending messages =============================================== */

  unsigned short      tp_reported;      /**< Report counter */
  unsigned            tp_plen;          /**< Size of tp_pending */
  unsigned            tp_pused;         /**< Used pends */
  tport_pending_t    *tp_pending;       /**< Pending requests */
  tport_pending_t    *tp_released;      /**< Released pends */

  /* ==== Send queue ===================================================== */

  msg_t             **tp_queue;		/**< Messages being sent */
  unsigned short      tp_qhead;		/**< Head of queue */

  msg_iovec_t        *tp_unsent;	/**< Pointer to first unsent iovec */
  size_t              tp_unsentlen;	/**< Number of unsent iovecs */

  msg_iovec_t        *tp_iov;		/**< Iovecs allocated for sending */
  size_t              tp_iovlen;	/**< Number of allocated iovecs */

  msg_t const        *tp_slogged;       /**< Last logged when sending */
  su_time_t           tp_stime;	        /**< Last time sent message */

  /* ==== Extensions  ===================================================== */

  tport_compressor_t *tp_comp;

  /* ==== Statistics  ===================================================== */

  struct {
    uint64_t sent_msgs, sent_errors, sent_bytes, sent_on_line;
    uint64_t recv_msgs, recv_errors, recv_bytes, recv_on_line;
  } tp_stats;
};

// freeswitch ============================= END!!!!!!!!!!! ===========================================


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
