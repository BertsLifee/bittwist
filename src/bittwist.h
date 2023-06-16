/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * bittwist - pcap based ethernet packet generator
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

#ifndef _BITTWIST_H_
#define _BITTWIST_H_

#include "def.h"

void send_packets(char *device, FILE *fp, char *trace_file);
void throttle(int pkt_len);
void load_packet(FILE *fp, int pkt_len, struct pcap_sf_pkthdr *header, char *trace_file);
void info(void);
void cleanup(int signum);
int32_t gmt2local(time_t t);
void hex_print(const uint8_t *cp, uint32_t length);
void ts_print(const struct timeval *tvp);
void notice(const char *fmt, ...);
void error(const char *fmt, ...);
void usage(void);

#endif /* !_BITTWIST_H_ */