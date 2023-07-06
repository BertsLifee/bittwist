/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * token_bucket - token bucket algorithm
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

/*
Reference:
https://ee.lbl.gov/papers/congavoid.pdf (Congestion Avoidance and Control)
https://en.wikipedia.org/wiki/Token_bucket

Sample usage with sample.c below:
---
#include "token_bucket.h"

int main()
{
    struct token_bucket tb;
    uint64_t bps = 1000000000;    // Target throughput at 1 Gbps
    uint64_t packet_size = 12112; // 1514 bytes
    uint64_t packets = 1000000;   // 1 million packets
    int i = 1;
    clock_gettime(CLOCK_MONOTONIC, &tb.last_add);
    do
    {
        while (!token_bucket_remove(&tb, packet_size, bps))
            usleep(1);
        i++; // packet sent
    } while (i <= packets);
    return 0;
}

$ gcc -I. sample.c token_bucket.c && time ./a.out
real    0m12.113s
user    0m0.391s
sys     0m0.392s
---

The time taken should be close to (packet_size_in_bits * packets) / bits_per_second
>>> 12112 * 1_000_000 / 1_000_000_000
12.112
*/

#ifndef _TOKEN_BUCKET_H_
#define _TOKEN_BUCKET_H_

#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <unistd.h>

struct token_bucket
{
    double tokens;            /* available tokens (bits) in bucket */
    struct timespec last_add; /* timestamp */
};

void token_bucket_add(struct token_bucket *tb, uint64_t bps);
bool token_bucket_remove(struct token_bucket *tb, uint64_t bits, uint64_t bps);

#endif /* !_TOKEN_BUCKET_H_ */
