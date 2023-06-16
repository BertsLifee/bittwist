#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_bittwist.py - bittwist Linux test suite
# Copyright (C) 2006 - 2023 Addy Yeow Chin Heng <ayeowch@gmail.com>
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
import re
import subprocess
import sys
from pathlib import Path

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
    command = f"sudo {devbin} -vv -i lo {pcap_file} {pcap_file}"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    assert "2 packets (68 bytes) sent" in output


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
    2000000 packets (3028000000 bytes) sent
    Throughput = 6211.94 Mbps
    Throughput = 6.21 Gbps
    Elapsed time = 3.899588 seconds
    """
    values = []  # Elapsed times in seconds.

    for ver, executable in executables:
        pcap_file = Path(__file__).resolve().parent / "pcap" / "1514.pcap"
        # 1M loop through 2 pcap files each containing 1 packet, 2M packets in total.
        command = f"sudo {executable} -i lo -l 1000000 -r 0 {pcap_file} {pcap_file}"
        logging.info(f"command={command}")

        output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
        output = output.decode("utf-8")
        lines = [line.strip() for line in output.strip().split("\n")]
        tail_output = "\n".join(lines[-5:])
        logging.info(f"output (last 5 lines)={tail_output}")

        assert "elapsed time" in output
        elapsed_time_line = lines[-1]
        logging.info(f"{ver} - {elapsed_time_line}")

        values.append(float(re.findall(r"\d+\.\d+", elapsed_time_line)[0]))

    # Elapsed times should be less than 1 second apart.
    assert all(abs(values[i] - values[i + 1]) <= 1 for i in range(len(values) - 1))
