/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * bittwiste - pcap capture file editor
 * Copyright (C) 2006 - 2023 Addy Yeow <ayeowch@gmail.com>
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

#ifndef _BITTWISTE_H_
#define _BITTWISTE_H_

#include "def.h"

void set_rand_in_addr_options(char *cp, struct in_addr *netnum, struct in_addr *netmask,
                              uint8_t *rand_bits);
void set_in_addr_options(char *optarg, struct in_addr_opt *opt);

void set_rand_in6_addr_options(char *cp, struct in6_addr *netaddr, struct in6_addr *netmask,
                               uint8_t *rand_bits);
void set_in6_addr_options(char *optarg, struct in6_addr_opt *opt);

void set_number_options(char *optarg, void *val_a, void *val_b, uint8_t *flag, size_t val_size);

void parse_header_options(int argc, char **argv);

void parse_trace(char *infile, char *outfile);

void truncate_packet(const uint8_t *pkt_data, struct pcap_sf_pkthdr *header, char *outfile,
                     FILE **fp_outfile);

void modify_packet(const uint8_t *pkt_data, struct pcap_sf_pkthdr *header, char *outfile,
                   FILE **fp_outfile);

void load_input_file(char *infile, FILE **fp);

void update_pcap_hdr(struct pcap_sf_pkthdr *header);

uint16_t parse_eth(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header);
void update_eth_hdr(struct ethhdr *eth_hdr);

uint16_t parse_arp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header);
void update_arp_hdr(struct arphdr *arp_hdr);

uint16_t parse_ip(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                  struct ip *ip_hdr, int flag);
void update_ip_cksum(struct ip *ip_hdr, uint8_t *ip_o, uint16_t *ip_hlb);
void update_ip_hdr(struct ip *ip_hdr, uint8_t *r, uint8_t *d, uint8_t *m);

uint16_t parse_ip6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header);
void update_ip6_hdr(struct ip6 *ip6_hdr);
void write_ip6_hdr(uint8_t *new_pkt_data, struct ip6 *ip6_hdr);

uint16_t parse_icmp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                    struct ip *ip_hdr);
void update_icmp_cksum(const uint8_t *pkt_data, struct ip *ip_hdr, struct icmphdr *icmp_hdr,
                       uint16_t *ip_hlb);
uint16_t parse_icmp6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                     struct ip6 *ip6_hdr);
void update_icmp6_cksum(const uint8_t *pkt_data, struct ip6 *ip6_hdr, struct icmp6hdr *icmp6_hdr);

uint16_t parse_tcp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                   struct ip *ip_hdr);
void update_tcp_cksum(const uint8_t *pkt_data, struct ip *ip_hdr, struct tcphdr *tcp_hdr,
                      uint16_t *ip_hlb, uint16_t *tcp_hlb, uint8_t *tcp_o);
uint16_t parse_tcp6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                    struct ip6 *ip6_hdr);
void update_tcp6_cksum(const uint8_t *pkt_data, struct ip6 *ip6_hdr, struct tcphdr *tcp_hdr,
                       uint16_t *tcp_hlb, uint8_t *tcp_o);
void update_tcp_hdr(struct tcphdr *tcp_hdr);

uint16_t parse_udp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                   struct ip *ip_hdr);
void update_udp_cksum(const uint8_t *pkt_data, struct ip *ip_hdr, struct udphdr *udp_hdr,
                      uint16_t *ip_hlb);
uint16_t parse_udp6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                    struct ip6 *ip6_hdr);
void update_udp6_cksum(const uint8_t *pkt_data, struct ip6 *ip6_hdr, struct udphdr *udp_hdr);
void update_udp_hdr(struct udphdr *udp_hdr);

void set_random_eth_addr(uint8_t *eth_addr);
void set_random_in_addr(struct in_addr *addr, struct in_addr_opt *opt);
void set_random_in6_addr(struct in6_addr *addr, struct in6_addr_opt *opt);
uint64_t get_random_number(uint64_t max_val);

struct ippseudo *create_ippseudo(struct ip *ip_hdr, uint16_t *ip_hlb);
struct ip6pseudo *create_ip6pseudo(struct ip6 *ip6_hdr);
uint16_t cksum(const void *cp, uint16_t len);

void info(void);

void notice(const char *, ...);

void error(const char *, ...);

int eth_aton(const char *a, uint8_t *eth_addr);

void usage(void);

#endif /* !_BITTWISTE_H_ */
