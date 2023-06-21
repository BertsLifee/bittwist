/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * template_pcap - Template pcap files to be used as input files for bittwiste
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

#ifndef _TEMPLATE_PCAP_H_
#define _TEMPLATE_PCAP_H_

extern const unsigned char TEMPLATE_PCAP_ETH[];
extern const size_t TEMPLATE_PCAP_ETH_LEN;

extern const unsigned char TEMPLATE_PCAP_ARP[];
extern const size_t TEMPLATE_PCAP_ARP_LEN;

extern const unsigned char TEMPLATE_PCAP_IP[];
extern const size_t TEMPLATE_PCAP_IP_LEN;

extern const unsigned char TEMPLATE_PCAP_IP6[];
extern const size_t TEMPLATE_PCAP_IP6_LEN;

extern const unsigned char TEMPLATE_PCAP_ICMP[];
extern const size_t TEMPLATE_PCAP_ICMP_LEN;

extern const unsigned char TEMPLATE_PCAP_ICMP6[];
extern const size_t TEMPLATE_PCAP_ICMP6_LEN;

extern const unsigned char TEMPLATE_PCAP_TCP[];
extern const size_t TEMPLATE_PCAP_TCP_LEN;

extern const unsigned char TEMPLATE_PCAP_IP6_TCP[];
extern const size_t TEMPLATE_PCAP_IP6_TCP_LEN;

extern const unsigned char TEMPLATE_PCAP_UDP[];
extern const size_t TEMPLATE_PCAP_UDP_LEN;

extern const unsigned char TEMPLATE_PCAP_IP6_UDP[];
extern const size_t TEMPLATE_PCAP_IP6_UDP_LEN;

#endif /* _TEMPLATE_PCAP_H_ */
