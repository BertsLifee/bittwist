#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_bittwist.py - bittwist Linux test suite
# Copyright (C) 2006 - 2023 Addy Yeow <ayeowch@gmail.com>
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

import hashlib
import logging
import subprocess
import sys
from pathlib import Path

from .benchmark_bittwist import get_ipg_from_output
from .benchmark_bittwist import get_stats_from_output

relbin = Path("/usr/local/bin/bittwist")
if not relbin.exists():
    sys.stderr.write(f"{relbin} is missing")
    sys.exit(1)

devbin = Path(__file__).resolve().parent.parent / "src" / "bittwist"
if not devbin.exists():
    sys.stderr.write(f"{devbin} is missing")
    sys.exit(1)

executables = [
    # Release version (publicly available)
    ("REL", relbin),
    # Dev version
    ("DEV", devbin),
]


def test_bittwist():
    """
    Quick test to check output of dev bittwist.
    """
    pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"sudo {devbin} -vv -i lo -l 0 -p 100 -c 100 {pcap_file} {pcap_file}"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    assert "sent = 100 packets, 27200 bits, 3400 bytes" in output


def test_bittwist_rel_vs_dev_hexdump():
    """
    Compare live hexdump of ip.pcap between release and dev bittwist.

    $ tcpdump -v -x -XX -r pcap/ip.pcap
    reading from file pcap/ip.pcap, link-type EN10MB (Ethernet), snapshot length 262144
    11:10:39.422956 IP (tos 0x0, ttl 64, id 12930, offset 0, flags [DF], proto TCP (6), length 20)
        localhost > localhost: [|tcp]
        0x0000:  0000 0000 0000 0000 0000 0000 0800 4500  ..............E.
        0x0010:  0014 3282 4000 4006 0a60 7f00 0001 7f00  ..2.@.@..`......
        0x0020:  0001                                     ..
    """
    hexdump_hashes = []

    for ver, executable in executables:
        pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
        command = (
            f"sudo {executable} -vv -i lo -l 5 {pcap_file} {pcap_file} {pcap_file}"
        )

        hexdump = []
        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.decode("utf-8")
        lines = [line.strip() for line in output.strip().split("\n")]
        for line in lines:
            if "0x" in line:
                hexdump.append(line)
        hexdump = "\n".join(hexdump)
        hexdump_hashes.append(hashlib.md5(hexdump.encode("utf-8")).hexdigest())

    assert len(set(hexdump_hashes)) == 1, "Hash mismatch in hexdump_hashes."


def test_bittwist_2M_speed():
    """
    Measure sending large number of packets on localhost.
    This should gives program's theoretical limit before hitting actual NIC.

    This throughput can be expected of current dev version:
    sent = 2000000 packets, 24224000000 bits, 3028000000 bytes
    throughput = 518668 pps, 6282.1104 Mbps, 6.2821 Gbps
    elapsed time = 3.856029 seconds
    """
    values = []  # Elapsed times in seconds.

    for ver, executable in executables:
        pcap_file = Path(__file__).resolve().parent / "pcap" / "1514.pcap"
        # 1M loop through 2 pcap files each containing 1 packet, 2M packets in total.
        command = f"sudo {executable} -i lo -l 1000000 -r 0 {pcap_file} {pcap_file}"
        logging.info(f"command={command}")

        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.decode("utf-8")
        elapsed_s = get_stats_from_output(output)["elapsed_s"]
        logging.info(f"{ver} - {elapsed_s}")
        values.append(elapsed_s)

    # Elapsed times should be less than 1 second apart.
    assert all(abs(values[i] - values[i + 1]) <= 1 for i in range(len(values) - 1))


def test_bittwist_1000us():
    """
    Check actual inter-packet gap when sending packets with 1000 us captured
    inter-packet gap.
    """
    pcap_file = Path(__file__).resolve().parent / "pcap" / "1000us.pcap"
    command = f"sudo {devbin} -v -i lo -l 10 {pcap_file}"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    ipg = get_ipg_from_output(output)

    # Skip low deltas from first packet in trace file.
    ipg = [v for v in ipg if v > 100]

    avg_ipg = int(sum(ipg) / len(ipg))
    logging.info(f"ipg={len(ipg)} - avg_ipg={avg_ipg} us")
    assert len(ipg) == 110
    assert 990 < avg_ipg < 1010  # 10 us tolerance.
