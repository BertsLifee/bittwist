/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * bittwist - pcap based ethernet packet generator
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

#ifndef _BITTWIST_H_
#define _BITTWIST_H_

#include "def.h"

/* inter-packet gap from trace file represented in nanoseconds and packets per second */
typedef struct
{
    uint64_t ns;
    int pps;
} ipg_t;

typedef struct
{
    FILE *fp;
    char *filename;
    bool nsec; /* set to true if we have timestamps in nanosecond resolution */
    ipg_t *ipg;
} trace_file_t;

void load_trace_files(int argc, char **argv);
void load_ipg(trace_file_t *trace_file);
void init_pcap(char *device);
void send_packets(trace_file_t *trace_file);
void sleep_ns(uint64_t ns);
void throttle(trace_file_t *trace_file, uint64_t pkts, int bits);
void load_packet(trace_file_t *trace_file, int pkt_len, struct pcap_sf_pkthdr *header);
void info(void);
void cleanup(int signum);
int32_t gmt2local(time_t t);
void hex_print(const uint8_t *cp, uint32_t length);
void ts_print(const struct timeval *tvp);
void notice(const char *fmt, ...);
void error(const char *fmt, ...);
void usage(void);

#endif /* !_BITTWIST_H_ */
