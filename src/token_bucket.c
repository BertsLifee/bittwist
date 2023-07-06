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

#include "token_bucket.h"

void token_bucket_add(struct token_bucket *tb, uint64_t bps)
{
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    uint64_t elapsed_ns =
        (now.tv_sec - tb->last_add.tv_sec) * 1000000000 + (now.tv_nsec - tb->last_add.tv_nsec);

    tb->tokens += bps * (double)elapsed_ns / 1000000000;
    tb->tokens = (tb->tokens < bps) ? tb->tokens : bps;
    tb->last_add = now;
}

bool token_bucket_remove(struct token_bucket *tb, uint64_t bits, uint64_t bps)
{
    if (tb->tokens < bits)
        token_bucket_add(tb, bps);

    if (tb->tokens < bits)
        return false;

    tb->tokens -= bits;
    return true;
}
