/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * def.h - Definition header file for Bit-Twist project
 * Copyright (C) 2006 - 2023 Addy Yeow Chin Heng <ayeowch@gmail.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#ifndef _DEF_H_
#define _DEF_H_

#include <ctype.h>
#include <errno.h>
#include <ifaddrs.h>
#include <limits.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define __USE_XOPEN /* using strptime from time.h */
#include <time.h>
#include <unistd.h>
#define _NET_IF_ARP_H_ /* OpenBSD's if.h takes in if_arp.h */
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#ifdef __BSD_VISIBLE /* Linux does not have net/if_dl.h */
#include <net/if_dl.h>
#endif
#include <pcap.h>

struct pcap_timeval
{
    bpf_int32 tv_sec; /* seconds */
    /*
     * PCAP_MAGIC: 6-digit followed by 000 (nanoseconds rounded from microseconds)
     * NSEC_PCAP_MAGIC: 9-digit (nanoseconds)
     */
    bpf_int32 tv_usec;
};

struct pcap_sf_pkthdr
{
    struct pcap_timeval ts; /* time stamp */
    bpf_u_int32 caplen;     /* length of portion present */
    bpf_u_int32 len;        /* length this packet (off wire) */
};

#define BITTWIST_VERSION "3.6"
#define BITTWISTE_VERSION BITTWIST_VERSION

#define ETHER_ADDR_LEN 6   /* Ethernet address length */
#define ETHER_HDR_LEN 14   /* Ethernet header length */
#define ETHER_MAX_LEN 1514 /* maximum frame length, excluding CRC */
#define ARP_HDR_LEN 28     /* Ethernet ARP header length */
#define IP_ADDR_LEN 4      /* IP address length */
#define IP_HDR_LEN 20      /* default IP header length */
#define IP6_HDR_LEN 40     /* default IPv6 header length */
#define ICMP_HDR_LEN 4     /* ICMP header length (up to checksum field only) */
#define ICMP6_HDR_LEN 4    /* ICMPv6 header length (up to checksum field only) */
#define TCP_HDR_LEN 20     /* default TCP header length */
#define UDP_HDR_LEN 8      /* UDP header length */

#define ETHERTYPE_IP 0x0800   /* IP protocol */
#define ETHERTYPE_IPV6 0x86dd /* IPv6 protocol */
#define ETHERTYPE_ARP 0x0806  /* address resolution protocol */

#ifndef IPPROTO_ICMP
#define IPPROTO_ICMP 1 /* internet control message protocol */
#endif

#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6 /* transmission control protocol */
#endif

#ifndef IPPROTO_UDP
#define IPPROTO_UDP 17 /* user datagram protocol */
#endif

#ifndef IPPROTO_ICMPV6
#define IPPROTO_ICMPV6 58 /* internet control message protocol version 6 */
#endif

/* bittwist */
#define LINERATE_MIN 0     /* Mbps (0 means no limit) */
#define LINERATE_MAX 10000 /* Mbps */
#define PKT_PAD 0x00       /* packet padding */
#define PPS_MAX 1000000    /* max. packets per second */
#define INTERVAL_MAX 86400 /* arbitrary maximum interval between packets in seconds */

/* bittwiste */
#define FIELD_SET 1          /* flag to overwrite field with new value */
#define FIELD_REPLACE 2      /* flag to overwrite matching value in field with new value */
#define FIELD_SET_RAND 3     /* flag to overwrite field with random value */
#define FIELD_REPLACE_RAND 4 /* flag to overwrite matching value in field with random value */

#define PAYLOAD_MAX 1500 /* maximum payload in bytes */

#define ETH 1 /* supported header specification (dummy values) */
#define ARP 2
#define IP 3
#define IP6 30
#define ICMP 4
#define ICMP6 40
#define TCP 5
#define UDP 6

#define IP_FO_MAX 7770             /* maximum IP fragment offset (number of 64-bit segments) */
#define IP6_FLOW_LABEL_MAX 1048575 /* 20-bit flow label: 0x00000 to 0xfffff (1048575) */
#define DS_FIELD_MAX 63            /* 6-bit DS field */
#define ECN_FIELD_MAX 3            /* 2-bit ECN field */

#define PCAP_HDR_LEN 16            /* pcap header length */
#define PCAP_MAGIC 0xa1b2c3d4      /* pcap magic number (timestamps in microsecond resolution)*/
#define NSEC_PCAP_MAGIC 0xa1b23c4d /* pcap magic number (timestamps in nanosecond resolution) */

#ifndef timespecisset
#define timespecisset(tsp) ((tsp)->tv_sec || (tsp)->tv_nsec)
#endif

#ifndef timespeccmp
#define timespeccmp(ctsp, ptsp, cmp)                                                               \
    (((ctsp)->tv_sec == (ptsp)->tv_sec) ? ((ctsp)->tv_nsec cmp(ptsp)->tv_nsec)                     \
                                        : ((ctsp)->tv_sec cmp(ptsp)->tv_sec))
#endif

#ifndef timespecsub
#define timespecsub(ctsp, ptsp, vtsp)                                                              \
    do                                                                                             \
    {                                                                                              \
        (vtsp)->tv_sec = (ctsp)->tv_sec - (ptsp)->tv_sec;                                          \
        (vtsp)->tv_nsec = (ctsp)->tv_nsec - (ptsp)->tv_nsec;                                       \
        if ((vtsp)->tv_nsec < 0)                                                                   \
        {                                                                                          \
            (vtsp)->tv_sec--;                                                                      \
            (vtsp)->tv_nsec += 1000000000L;                                                        \
        }                                                                                          \
    } while (0)
#endif

/* Ethernet header */
struct ether_header
{
    uint8_t ether_dhost[ETHER_ADDR_LEN];
    uint8_t ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;
};

/* 48-bit Ethernet address */
struct ether_addr
{
    uint8_t octet[ETHER_ADDR_LEN];
};

/* Ethernet ARP header */
struct arphdr
{
    uint16_t ar_hrd;                /* format of hardware address */
#define ARPHRD_ETHER 1              /* ethernet hardware format */
#define ARPHRD_IEEE802 6            /* token-ring hardware format */
#define ARPHRD_ARCNET 7             /* arcnet hardware format */
#define ARPHRD_FRELAY 15            /* frame relay hardware format */
#define ARPHRD_IEEE1394 24          /* firewire hardware format */
    uint16_t ar_pro;                /* format of protocol address */
    uint8_t ar_hln;                 /* length of hardware address */
    uint8_t ar_pln;                 /* length of protocol address */
    uint16_t ar_op;                 /* one of: */
#define ARPOP_REQUEST 1             /* request to resolve address */
#define ARPOP_REPLY 2               /* response to previous request */
#define ARPOP_REVREQUEST 3          /* request protocol address given hardware */
#define ARPOP_REVREPLY 4            /* response giving protocol address */
#define ARPOP_INVREQUEST 8          /* request to identify peer */
#define ARPOP_INVREPLY 9            /* response identifying peer */
    uint8_t ar_sha[ETHER_ADDR_LEN]; /* sender hardware address */
    uint8_t ar_spa[IP_ADDR_LEN];    /* sender protocol address */
    uint8_t ar_tha[ETHER_ADDR_LEN]; /* target hardware address */
    uint8_t ar_tpa[IP_ADDR_LEN];    /* target protocol address */
};

/* IPv4 header */
struct ip
{
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t ip_hl : 4, /* header length */
        ip_v : 4;      /* version */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t ip_v : 4, /* version */
        ip_hl : 4;    /* header length */
#endif
    uint8_t ip_tos;                /* type of service */
    uint16_t ip_len;               /* total length */
    uint16_t ip_id;                /* identification */
    uint16_t ip_off;               /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* dont fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    uint8_t ip_ttl;                /* time to live */
    uint8_t ip_p;                  /* protocol */
    uint16_t ip_sum;               /* checksum */
    struct in_addr ip_src, ip_dst; /* source and destination address */
} __packed_ip;

/* IPv6 header */
struct ip6
{
    union
    {
        struct ip6_hdrctl
        {
            uint32_t ip6_un1_flow; /* 4-bit version, 8-bit traffic class, 20-bit flow label */
            uint16_t ip6_un1_plen; /* 16-bit payload length */
            uint8_t ip6_un1_nxt;   /* 8-bit next header */
            uint8_t ip6_un1_hlim;  /* 8-bit hop limit */
        } ip6_un1;
        uint8_t ip6_un2_vfc; /* 4-bit version, top 4-bit traffic class */
    } ip6_ctlun;
    struct in6_addr ip6_src; /* 128-bit source address */
    struct in6_addr ip6_dst; /* 128-bit destination address */
} __packed_ip6;

/*
Sample IPv6 packet showing how Wireshark decodes flow info (ip6_flow):

Frame 1: 86 bytes on wire (688 bits), 86 bytes captured (688 bits)
Ethernet II, Src: aa:aa:aa:aa:aa:aa (aa:aa:aa:aa:aa:aa), Dst: bb:bb:bb:bb:bb:bb (bb:bb:bb:bb:bb:bb)
Internet Protocol Version 6, Src: 2606:4700:4700::64, Dst: 2606:4700:4700::6400
    0110 ....                               = Version: 6
    .... 0000 0000 .... .... .... .... .... = Traffic Class: 0x00 (DSCP: CS0, ECN: Not-ECT)
    .... .... .... 0011 0101 0001 1011 0011 = Flow Label: 0x351b3
    Payload Length: 32
    Next Header: TCP (6)
    Hop Limit: 53
    Source Address: 2606:4700:4700::64
    Destination Address: 2606:4700:4700::6400
Transmission Control Protocol, Src Port: 30000, Dst Port: 60000, Seq: 1, Ack: 1, Len: 0
*/
#define ip6_flow ip6_ctlun.ip6_un1.ip6_un1_flow
#define ip6_plen ip6_ctlun.ip6_un1.ip6_un1_plen
#define ip6_nxt ip6_ctlun.ip6_un1.ip6_un1_nxt
#define ip6_hlim ip6_ctlun.ip6_un1.ip6_un1_hlim

#define IP6_FLOWLABEL_MASK (htonl(0x000fffff)) /* 20-bit flow label (network byte order) */

/* IPv4 pseudo header for computing TCP and UDP checksums */
struct ippseudo
{
    struct in_addr ippseudo_src; /* source address */
    struct in_addr ippseudo_dst; /* destination address */
    uint8_t ippseudo_pad;        /* pad, must be zero */
    uint8_t ippseudo_p;          /* protocol */
    uint16_t ippseudo_len;       /* protocol length */
};

/* IPv6 pseudo header for computing ICMPv6, TCP and UDP checksums */
struct ip6pseudo
{
    struct in6_addr ip6pseudo_src; /* 128-bit source address */
    struct in6_addr ip6pseudo_dst; /* 128-bit destination address */
    uint32_t ip6pseudo_len;        /* 32-bit upper-layer packet length */
    uint8_t ip6pseudo_zero[3];     /* 24-bit zeros */
    uint8_t ip6pseudo_nxt;         /* 8-bit next header */
};

/* ICMP header (up to checksum field only) */
struct icmphdr
{
    uint8_t icmp_type;   /* type field */
    uint8_t icmp_code;   /* code field */
    uint16_t icmp_cksum; /* checksum field */
};

/* ICMPv6 header (up to checksum field only) */
struct icmp6hdr
{
    uint8_t icmp6_type;   /* type field */
    uint8_t icmp6_code;   /* code field */
    uint16_t icmp6_cksum; /* checksum field */
};

/* TCP header */
struct tcphdr
{
    uint16_t th_sport; /* source port */
    uint16_t th_dport; /* destination port */
    uint32_t th_seq;   /* sequence number */
    uint32_t th_ack;   /* acknowledgment number */
#if BYTE_ORDER == LITTLE_ENDIAN
    uint8_t th_x2 : 4, /* (unused) */
        th_off : 4;    /* data offset in number of 32-bit words */
#endif
#if BYTE_ORDER == BIG_ENDIAN
    uint8_t th_off : 4, /* data offset in number of 32-bit words */
        th_x2 : 4;      /* (unused) */
#endif
    uint8_t th_flags;
#define TH_FIN 0x01  /* no more data from sender */
#define TH_SYN 0x02  /* synchronize sequence numbers */
#define TH_RST 0x04  /* reset the connection */
#define TH_PUSH 0x08 /* push function */
#define TH_ACK 0x10  /* acknowledgment field is significant */
#define TH_URG 0x20  /* urgent pointer field is significant */
#define TH_ECE 0x40  /* explicit congestion notification echo */
#define TH_CWR 0x80  /* congestion window reduced */
#define TH_FLAGS (TH_FIN | TH_SYN | TH_RST | TH_PUSH | TH_ACK | TH_URG | TH_ECE | TH_CWR)
    uint16_t th_win; /* window */
    uint16_t th_sum; /* checksum */
    uint16_t th_urp; /* urgent pointer */
};

/* UDP header */
struct udphdr
{
    uint16_t uh_sport; /* source port */
    uint16_t uh_dport; /* destination port */
    uint16_t uh_ulen;  /* udp length */
    uint16_t uh_sum;   /* udp checksum */
};

/*
 * Structures for bittwiste header specific options.
 */
struct ethopt
{
    uint8_t ether_old_dhost[ETHER_ADDR_LEN];
    uint8_t ether_new_dhost[ETHER_ADDR_LEN];
    uint8_t ether_dhost_flag;
    uint8_t ether_old_shost[ETHER_ADDR_LEN];
    uint8_t ether_new_shost[ETHER_ADDR_LEN];
    uint8_t ether_shost_flag;
    uint16_t ether_type;
};

struct arpopt
{
    uint16_t ar_op; /* opcode */
    uint8_t ar_op_flag;
    uint8_t ar_old_sha[ETHER_ADDR_LEN]; /* sender hardware address */
    uint8_t ar_new_sha[ETHER_ADDR_LEN];
    uint8_t ar_sha_flag;
    uint8_t ar_old_spa[IP_ADDR_LEN]; /* sender protocol address */
    uint8_t ar_new_spa[IP_ADDR_LEN];
    uint8_t ar_spa_flag;
    uint8_t ar_old_tha[ETHER_ADDR_LEN]; /* target hardware address */
    uint8_t ar_new_tha[ETHER_ADDR_LEN];
    uint8_t ar_tha_flag;
    uint8_t ar_old_tpa[IP_ADDR_LEN]; /* target protocol address */
    uint8_t ar_new_tpa[IP_ADDR_LEN];
    uint8_t ar_tpa_flag;
};

struct ipopt
{
    uint8_t ip_ds_field; /* 6-bit DS field (first 6-bit of 8-bit type of service field) */
    uint8_t ip_ds_field_flag;
    uint8_t ip_ecn_field; /* 2-bit ECN field (last 2-bit of 8-bit type of service field) */
    uint8_t ip_ecn_field_flag;
    uint16_t ip_old_id; /* identification */
    uint16_t ip_new_id;
    uint8_t ip_id_flag;
    uint8_t ip_flag_r; /* reserved bit */
    uint8_t ip_flag_d; /* don't fragment bit */
    uint8_t ip_flag_m; /* more fragment bit */
    uint8_t ip_flags_flag;
    uint16_t ip_fo; /* fragment offset in bytes */
    uint8_t ip_fo_flag;
    uint8_t ip_old_ttl; /* time to live */
    uint8_t ip_new_ttl;
    uint8_t ip_ttl_flag;
    uint8_t ip_old_p; /* protocol */
    uint8_t ip_new_p;
    uint8_t ip_p_flag;
    struct in_addr ip_old_src; /* source address */
    struct in_addr ip_new_src;
    uint8_t ip_src_flag;
    struct in_addr ip_old_dst; /* destination address */
    struct in_addr ip_new_dst;
    uint8_t ip_dst_flag;
};

struct ip6opt
{
    uint8_t ip6_ds_field; /* 6-bit DS field (first 6-bit of 8-bit traffic class field) */
    uint8_t ip6_ds_field_flag;
    uint8_t ip6_ecn_field; /* 2-bit ECN field  (last 2-bit of 8-bit traffic class field) */
    uint8_t ip6_ecn_field_flag;
    uint32_t ip6_flow_label; /* 20-bit flow label */
    uint8_t ip6_flow_label_flag;
    uint8_t ip6_old_next_header; /* 8-bit next header */
    uint8_t ip6_new_next_header;
    uint8_t ip6_next_header_flag;
    uint8_t ip6_old_hop_limit; /* 8-bit hop limit */
    uint8_t ip6_new_hop_limit;
    uint8_t ip6_hop_limit_flag;
    struct in6_addr ip6_old_src; /* 128-bit source address */
    struct in6_addr ip6_new_src;
    uint8_t ip6_src_flag;
    struct in6_addr ip6_old_dst; /* 128-bit destination address */
    struct in6_addr ip6_new_dst;
    uint8_t ip6_dst_flag;
};

struct icmpopt
{
    uint8_t icmp_type; /* type of message */
    uint8_t icmp_type_flag;
    uint8_t icmp_code; /* type sub code */
    uint8_t icmp_code_flag;
};

struct icmp6opt
{
    uint8_t icmp6_type; /* type of message */
    uint8_t icmp6_type_flag;
    uint8_t icmp6_code; /* type sub code */
    uint8_t icmp6_code_flag;
};

struct tcpopt
{
    uint16_t th_old_sport; /* source port */
    uint16_t th_new_sport;
    uint8_t th_sport_flag;
    uint16_t th_old_dport; /* destination port */
    uint16_t th_new_dport;
    uint8_t th_dport_flag;
    uint32_t th_old_seq; /* sequence number */
    uint32_t th_new_seq;
    uint8_t th_seq_flag;
    uint32_t th_old_ack; /* acknowledgment number */
    uint32_t th_new_ack;
    uint8_t th_ack_flag;
    uint8_t th_flag_c; /* CWR */
    uint8_t th_flag_e; /* ECE */
    uint8_t th_flag_u; /* URG */
    uint8_t th_flag_a; /* ACK */
    uint8_t th_flag_p; /* PSH */
    uint8_t th_flag_r; /* RST */
    uint8_t th_flag_s; /* SYN */
    uint8_t th_flag_f; /* FIN */
    uint8_t th_flags_flag;
    uint16_t th_win; /* window */
    uint8_t th_win_flag;
    uint16_t th_urp; /* urgent pointer */
    uint8_t th_urp_flag;
};

struct udpopt
{
    uint16_t uh_old_sport; /* source port */
    uint16_t uh_new_sport;
    uint8_t uh_sport_flag;
    uint16_t uh_old_dport; /* destination port */
    uint16_t uh_new_dport;
    uint8_t uh_dport_flag;
};

#endif /* !_DEF_H_ */
