#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# benchmark_bittwist.py - Generate bittwist benchmark data
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

import argparse
import json
import logging
import re
import subprocess
import sys
from pathlib import Path

bittwist_bin = Path(__file__).resolve().parent.parent / "src" / "bittwist"
if not bittwist_bin.exists():
    sys.stderr.write(f"{bittwist_bin} is missing")
    sys.exit(1)

bittwiste_bin = Path(__file__).resolve().parent.parent / "src" / "bittwiste"
if not bittwiste_bin.exists():
    sys.stderr.write(f"{bittwiste_bin} is missing")
    sys.exit(1)

out_pcap_file = Path(__file__).resolve().parent / "pcap" / "out.pcap"


def get_ipg_from_output(output):
    """
    Parse bittwist verbose output and return a list of all inter-packet gap
    values in microseconds.
    """
    ipg = []

    # Look for lines matching pattern e.g. "10:53:46.295748 #6 (42 bytes)"
    pattern = r"(\d{2}):(\d{2}):(\d{2})\.(\d+) #\d+ \(\d+ bytes\)"

    prev_us = None
    lines = output.split("\n")
    for line in lines:
        match = re.match(pattern, line)
        if not match:
            continue
        hh, mm, ss, us = match.groups()
        curr_us = (
            (int(hh) * 3_600_000_000)
            + (int(mm) * 60_000_000)
            + (int(ss) * 1_000_000)
            + int(us)
        )
        if prev_us:
            ipg.append(curr_us - prev_us)
        prev_us = curr_us

    return ipg


def get_stats_from_output(output):
    """
    Parse bittwist output and return the stats.
    """
    lines = [line.strip() for line in output.strip().split("\n")][-3:]
    """
    sent = 585937 packets, 299999744 bits, 37499968 bytes
    throughput = 19531 pps, 10.0000 Mbps, 0.0100 Gbps
    elapsed time = 29.999981 seconds
    """
    match = re.match(r"sent = (\d+) packets, (\d+) bits", lines[0])
    sent_pkts, sent_bits = match.groups()

    match = re.match(r"throughput = (\d+) pps, (\d+\.\d+) Mbps", lines[1])
    throughput_pps, throughput_mbps = match.groups()

    match = re.match(r"elapsed time = (\d+\.\d+) seconds", lines[2])
    elapsed_s = match.groups()[0]

    stats = {
        "sent_pkts": int(sent_pkts),
        "sent_bits": int(sent_bits),
        "throughput_pps": int(throughput_pps),
        "throughput_mbps": float(throughput_mbps),
        "elapsed_s": float(elapsed_s),
    }
    return stats


def percent_change(new_val, old_val):
    change = (new_val - old_val) / old_val * 100
    return round(change, 6)


def write_json(json_file, data):
    with open(json_file, "w") as f:
        f.write(json.dumps(data, indent=2))
    logging.info(f"wrote {json_file}")


def benchmark_pps_ipg():
    """
    Single CPU thread benchmark that generates benchmark data by sending
    packets using packets per second (PPS) inter-packet gap (IPG) with set
    number of packets onto the loopback interface.
    """
    out_json_file = Path(__file__).resolve().parent / "benchmark_pps_ipg.json"
    benchmark_results = []

    # Each pps takes about (20s + 40s + 60s + 80s + 100s) = 300s
    # In total, pps_vals takes 300s * 4 = 20 minutes
    pps_vals = (0.5, 1, 100, 500000)
    for pps in pps_vals:
        pps_data = {pps: []}

        for n in range(5):
            # Number of packets to send for this test.
            # This is formulated such that each increment of n increases the
            # test by 20 seconds in total expected duration.
            # As we are testing for IPG accuracy, such incremental duration
            # will allow us to check for possible drift in the benchmark
            # results; increasing drift may indicate buggy timing code.
            pkts = int((n + 1) * (pps * 20))

            # Given the PPS, calculate its IPG in microseconds.
            expected_ipg_us = int(1_000_000 / pps)

            expected_elapsed_s = pkts * expected_ipg_us / 1_000_000.0

            # Prepare the packets with the required IPG for this test.
            cmd = f"{bittwiste_bin} -I udp -O {out_pcap_file} -N {pkts} -G {expected_ipg_us}"
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

            # Send the packets using their existing IPG.
            cmd = f"sudo taskset --cpu-list 0 nice -20 {bittwist_bin} -v -i lo {out_pcap_file}"
            logging.info(f"pps={pps} - pkts={pkts} - cmd={cmd}")
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            output = output.decode("utf-8")

            ipg = get_ipg_from_output(output)
            actual_ipg_us = round(sum(ipg) / len(ipg), 6)
            actual_elapsed_s = get_stats_from_output(output)["elapsed_s"]

            pps_data[pps].append(
                {
                    "pkts": pkts,
                    "ipg_us": {
                        "expected": expected_ipg_us,
                        "actual": actual_ipg_us,
                        "diff": percent_change(actual_ipg_us, expected_ipg_us),
                    },
                    "elapsed_s": {
                        "expected": expected_elapsed_s,
                        "actual": actual_elapsed_s,
                        "diff": percent_change(actual_elapsed_s, expected_elapsed_s),
                    },
                }
            )

        benchmark_results.append(pps_data)

    write_json(out_json_file, benchmark_results)


def benchmark_max_throughput(iface, smac, dmac, sip, dip):
    """
    On-wire benchmark that generates benchmark data by sending packets at the
    specified throughputs in Mbps with set number of packets onto an actual
    network interface card.
    """
    out_json_file = Path(__file__).resolve().parent / "benchmark_max_throughput.json"
    benchmark_results = []

    # 21 tests.
    mbps_vals = (10, 100, 1000)  # Mbps
    pkt_lens = (64, 128, 256, 512, 1024, 1280, 1514)  # bytes

    # We want each test to take about 60s; 21 minutes in total.
    for expected_mbps in mbps_vals:
        mbps_data = {expected_mbps: []}

        for pkt_len in pkt_lens:
            expected_elapsed_s = 60

            # Number of packets to send for this test.
            total_bits = expected_mbps * 1000 * 1000 * expected_elapsed_s
            pkts = int(total_bits / (pkt_len * 8))

            expected_pps = int(pkts / expected_elapsed_s)

            # 1 + 100K UDP packets with correct MAC addresses.
            cmd = f"{bittwiste_bin} -I udp -O {out_pcap_file}.1 -N {pkts - 1} -T eth -s {smac} -d {dmac}"
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

            # Correct IP addresses.
            cmd = f"{bittwiste_bin} -I {out_pcap_file}.1 -O {out_pcap_file}.2 -T ip -s {sip} -d {dip}"
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

            # Extend each packet to the required length.
            # e.g. 64 bytes packet:
            # - Ethernet header = 14 bytes
            # - IP header       = 20 bytes
            # - UDP header      = 8 bytes
            # - Payload         = 64 - headers = 22 bytes
            payload = "0" * (pkt_len - (14 + 20 + 8)) * 2
            cmd = f"{bittwiste_bin} -I {out_pcap_file}.2 -O {out_pcap_file} -X {payload} -L 4 -T udp"
            subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

            # Remove intermediary pcap files.
            Path(f"{out_pcap_file}.1").unlink()
            Path(f"{out_pcap_file}.2").unlink()

            # Send the packets at the specified linerate in Mbps.
            cmd = f"sudo taskset --cpu-list 0 nice -20 {bittwist_bin} -i {iface} -r {expected_mbps} {out_pcap_file}"
            logging.info(f"pkt_len={pkt_len} - pkts={pkts} - cmd={cmd}")
            output = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
            output = output.decode("utf-8")
            stats = get_stats_from_output(output)

            assert stats["sent_pkts"] == pkts

            actual_pps = stats["throughput_pps"]
            actual_mbps = stats["throughput_mbps"]
            actual_elapsed_s = stats["elapsed_s"]

            mbps_data[expected_mbps].append(
                {
                    "pkt_len": pkt_len,
                    "pkts": pkts,
                    "pps": {
                        "expected": expected_pps,
                        "actual": actual_pps,
                        "diff": percent_change(actual_pps, expected_pps),
                    },
                    "mbps": {
                        "expected": expected_mbps,
                        "actual": actual_mbps,
                        "diff": percent_change(actual_mbps, expected_mbps),
                    },
                    "elapsed_s": {
                        "expected": expected_elapsed_s,
                        "actual": actual_elapsed_s,
                        "diff": percent_change(actual_elapsed_s, expected_elapsed_s),
                    },
                }
            )

        benchmark_results.append(mbps_data)

    write_json(out_json_file, benchmark_results)


def main():
    log_format = "%(levelname)s - %(asctime)s - %(funcName)s - %(message)s"
    logging.basicConfig(level="DEBUG", format=log_format)

    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--tests", nargs="+", default=[], help="Benchmark to run. Default: All"
    )

    # On-wire setup.
    parser.add_argument("--iface", default="lo", help="Outbound network interface")
    parser.add_argument("--smac", default="00:00:00:00:00:00", help="Source MAC")
    parser.add_argument("--dmac", default="00:00:00:00:00:00", help="Destination MAC")
    parser.add_argument("--sip", default="127.0.0.1", help="Source IP")
    parser.add_argument("--dip", default="127.0.0.1", help="Destination IP")

    args = parser.parse_args()

    # If not set, run all tests.
    tests = args.tests

    if not tests or "benchmark_pps_ipg" in tests:
        benchmark_pps_ipg()

    if not tests or "benchmark_max_throughput" in tests:
        benchmark_max_throughput(args.iface, args.smac, args.dmac, args.sip, args.dip)


if __name__ == "__main__":
    sys.exit(main())
