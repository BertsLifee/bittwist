#!/usr/bin/env python
# SPDX-License-Identifier: GPL-2.0-or-later
#
# test_bittwiste.py - bittwiste Linux test suite
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
import subprocess
import sys
from pathlib import Path

bin = Path(__file__).resolve().parent.parent / "src" / "bittwiste"
if not bin.exists():
    sys.stderr.write(f"{bin} is missing")
    sys.exit(1)

out_pcap_file = Path(__file__).resolve().parent / "pcap" / "out.pcap"


def test_bittwiste_copy():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file}"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    in_checksum = hashlib.md5(open(in_pcap_file, "rb").read()).hexdigest()
    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert in_checksum == out_checksum


def test_bittwiste_templates():
    templates = [
        ("eth", "ef94560b8178c9c5d1e913dcc945ce54"),
        ("arp", "d5b379f8a20376e1b63bb8338dbf877c"),
        ("ip", "f29a94f834e7cc8ea668520136d50eea"),
        ("ip6", "959d8f64bd4db5c0c735f3d7b6e8f0cb"),
        ("icmp", "cd039cc28047192408bb2e37d0ece168"),
        ("icmp6", "dd5f5162c0666731e7389e4441a00d0b"),
        ("tcp", "47eb30890319537e780e597843345189"),
        ("ip6tcp", "b3795eb0b5b315f6d156bb2c48424062"),
        ("udp", "f3f26f6e1234741ff89d5205d20a7802"),
        ("ip6udp", "01f51a34b5cea651547437288ad3431a"),
    ]
    for template, expected_checksum in templates:
        command = f"{bin} -I {template} -O {out_pcap_file}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_template_udp_sport():
    command = f"{bin} -I udp -O {out_pcap_file} -T udp -s 0"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "c132a9cc34f8f951c6835655a061e5fc"


def test_bittwiste_template_repeat_tcp_dport_rand():
    command = f"{bin} -I ip6tcp -O {out_pcap_file} -N 10000 -P 1 -T tcp -d rand"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    assert "10001 packets (1020126 bytes) written" in output

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "38f4a09f4228898971269ee920ec0c12"


def test_bittwiste_max_ip_payload():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp.pcap"
    payload = "0" * 1500 * 2  # 1500 bytes max payload.
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -R 1 -L 3 -X {payload} -T ip"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    assert "1 packets (1554 bytes) written" in output

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "5386b37145d52979ade052383742b29c"


def test_bittwiste_max_tcp_payload():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp.pcap"
    payload = "f" * 1500 * 2  # 1500 bytes max payload.
    command = (
        f"{bin} -I {in_pcap_file} -O {out_pcap_file} -R 1 -L 4 -X {payload} -T tcp"
    )
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    assert "1 packets (1554 bytes) written" in output

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "d66db2ba1345b1bb7e63270556915066"


def test_bittwiste_icmp_echo():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T icmp -t 0"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "decdb8f44253801bcfdc845387d6f6cb"


def test_bittwiste_layer_2():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -L 2"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    # 24 bytes (pcap file header)
    # 16 bytes (pcap packet header)
    # 14 bytes (Ethernet header)
    assert "1 packets (54 bytes) written" in output

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "284991bf006227abc978df0531206f83"


def test_bittwiste_layer_3():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -L 3"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    # 24 bytes (pcap file header)
    # 16 bytes (pcap packet header)
    # 14 bytes (Ethernet header)
    # 20 bytes (IP header)
    assert "1 packets (74 bytes) written" in output

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "911ad3bc2d34ce31a33f46eeedf0d003"


def test_bittwiste_layer_4():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -L 4"
    output = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)
    output = output.decode("utf-8")
    # 24 bytes (pcap file header)
    # 16 bytes (pcap packet header)
    # 14 bytes (Ethernet header)
    # 20 bytes (IP header)
    # 8 bytes (UDP header)
    assert "1 packets (82 bytes) written" in output

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "4859e9da19006513d8836686ad10b87a"


def test_bittwiste_no_checksum():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -L 4 -C"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "36858da4295e35c470b0de4955f3e44d"


def test_bittwiste_link_type():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -M 0"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "58018d4978c0ac9bc517d0686505553a"


def test_bittwiste_delete_offset():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -D 15-9999"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "284991bf006227abc978df0531206f83"


def test_bittwiste_range():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -R 2-3"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "011f483f5bf0a21039dfc345040c696c"


def test_bittwiste_timeframe():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -S 01/06/2023,14:56:32-01/06/2023,14:56:33"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "011f483f5bf0a21039dfc345040c696c"


def test_bittwiste_nanosecond_ts_pcap():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "nanosecond-ts.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -S 08/06/2023,09:09:29-08/06/2023,09:09:29"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "c621b20df8bc13975dbaefde03f17acc"


def test_bittwiste_repeat():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "nanosecond-ts.pcap"
    opts = [
        ("-N 1", "243327564647893dda909185b545f72c"),
        ("-R 1 -N 1", "73a57e6dbc987767164b504ad70cd6e0"),
        ("-R 2-4 -N 1000", "77e31e7c751cc03dbe888ae7dcb33d71"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_eth_dst_mac():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T eth -d bb:bb:bb:bb:bb:bb,aa:bb:cc:dd:ee:ff"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "fecc1048a00288d602bf7b84e023e8a2"


def test_bittwiste_eth_src_mac():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T eth -s aa:aa:aa:aa:aa:aa,00:11:22:33:44:55"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "933cb03f4ef0d2b57a1a0bd7763c20ec"


def test_bittwiste_eth_type():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T eth -t ip"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "2bedce3bb211e95b6b2f29978e6605e6"


def test_bittwiste_arp_opcode():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "arp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T arp -o 2"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "94318ecfee20fb3b402639d8f91093dc"


def test_bittwiste_arp_smac():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "arp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T arp -s 22:22:22:22:22:22"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "0538da849487db578c53b1678222f6f1"


def test_bittwiste_arp_sip():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "arp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T arp -p 192.168.0.1"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "c6747231d370b90a70dbc442dd4bdf6d"


def test_bittwiste_arp_tmac():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "arp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T arp -t 22:22:22:22:22:22"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "bc45ddf0a6488d8ba0107ce0f16a7a97"


def test_bittwiste_arp_tip():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "arp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T arp -q 192.168.0.1"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "0670268132833a757e42580584463fa2"


def test_bittwiste_ip_ds_field():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    # From RFC 4594
    # Some of the service class name mapping to DS field value:
    # ---------------------------------------------------------------
    # Service class name     DSCP name  DSCP value (binary, hex, int)
    # ---------------------------------------------------------------
    # Standard               CS0        000000, 0x00, 0
    # Low-priority data      CS1        001000, 0x08, 8
    # OAM                    CS2        010000, 0x10, 16
    # Broadcast video        CS3        011000, 0x18, 24
    # Real-time interactive  CS4        100000, 0x20, 32
    # ---------------------------------------------------------------
    values = [
        ("0", "f29a94f834e7cc8ea668520136d50eea"),
        ("0x00", "f29a94f834e7cc8ea668520136d50eea"),  # Standard
        ("8", "b0c9c5d4adf93e8e1749bd7844015da7"),
        ("0x08", "b0c9c5d4adf93e8e1749bd7844015da7"),  # Low-priority data
        ("16", "f247e8932c3b5405e82a9410d1250489"),
        ("0x10", "f247e8932c3b5405e82a9410d1250489"),  # OAM
        ("24", "c579867ac611fdadf43c9ec3a6a2eb72"),
        ("0x18", "c579867ac611fdadf43c9ec3a6a2eb72"),  # Broadcast video
        ("32", "d08af4ed967605d4a3e9c0ca24c4b886"),
        ("0x20", "d08af4ed967605d4a3e9c0ca24c4b886"),  # Real-time interactive
    ]
    for value, expected_checksum in values:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -c {value}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip_ecn_field():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    values = [
        # From RFC 3168
        # ECN: Explicit Congestion Notification
        # ECT: ECN-Capable Transport
        # CE: Congestion Experienced
        # To set ECN field, choose one of the 4 codepoints below:
        # ----------------------------------
        #             ECN FIELD
        # ----------------------------------
        # ECT  CE  Hex value  Codepoint name
        # ----------------------------------
        # 0    0   0x00       Not-ECT
        # 0    1   0x01       ECT(1)
        # 1    0   0x02       ECT(0)
        # 1    1   0x03       CE
        # ----------------------------------
        ("0", "f29a94f834e7cc8ea668520136d50eea"),
        ("0x00", "f29a94f834e7cc8ea668520136d50eea"),  # 0b00000011 Not-ECT
        ("1", "c05a433d6fe82316368826af20fb57b3"),
        ("0x01", "c05a433d6fe82316368826af20fb57b3"),  # 0b00000001 ECT(1)
        ("2", "6f9cdfa72ad388f581c1ee3332fec340"),
        ("0x02", "6f9cdfa72ad388f581c1ee3332fec340"),  # 0b00000010 ECT(0)
        ("3", "8f738d20218243bfe371d01fe2134c3a"),
        ("0x03", "8f738d20218243bfe371d01fe2134c3a"),  # 0b00000011 CE
    ]
    for value, expected_checksum in values:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -e {value}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip_id():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -i 65535"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "3a856b4b58cb606fca2899fdb77de035"


def test_bittwiste_ip_flags():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    flags = [
        ("-", "5764a63494d331bae4ba6289583de7eb"),
        ("r", "273e0444f43862fd3a1adde85c259673"),
        ("d", "f29a94f834e7cc8ea668520136d50eea"),
        ("m", "a744c0b40197f83cbf08f48349346c07"),
        ("rdm", "027d1b001a781901aa1d3efabf938e9d"),
    ]
    for flag, expected_checksum in flags:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -f {flag}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip_offset():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -o 7770"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "8f6a26bb30dbc03fb10b7d39c8976fc8"


def test_bittwiste_ip_ttl():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -t 10"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "11ea67ba2c7bfac96dd9b5718b0750ae"


def test_bittwiste_ip_proto():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -p 255"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "6518e609dd35cbbae72fa363236a1d18"


def test_bittwiste_ip_sip():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -s 1.1.1.1"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "2f4d5757b9b291930850e5bc5d312081"


def test_bittwiste_ip_dip():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "ip.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip -d 1.1.1.1"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "19ab454b058b686ff297cabf962d91ad"


def test_bittwiste_ip6_ds_field():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    # From RFC 4594
    # Some of the service class name mapping to DS field value:
    # ---------------------------------------------------------------
    # Service class name     DSCP name  DSCP value (binary, hex, int)
    # ---------------------------------------------------------------
    # Standard               CS0        000000, 0x00, 0
    # Low-priority data      CS1        001000, 0x08, 8
    # OAM                    CS2        010000, 0x10, 16
    # Broadcast video        CS3        011000, 0x18, 24
    # Real-time interactive  CS4        100000, 0x20, 32
    # ---------------------------------------------------------------
    values = [
        ("0", "fd907f31094c4937012285acf200e28f"),
        ("0x00", "fd907f31094c4937012285acf200e28f"),  # Standard
        ("8", "d4c72d18d6f83f7010ff3caccaa976b6"),
        ("0x08", "d4c72d18d6f83f7010ff3caccaa976b6"),  # Low-priority data
        ("16", "c6bd6e916e953525253b003000a2a7ba"),
        ("0x10", "c6bd6e916e953525253b003000a2a7ba"),  # OAM
        ("24", "2f4a2716507d916e0fcdca596c96163a"),
        ("0x18", "2f4a2716507d916e0fcdca596c96163a"),  # Broadcast video
        ("32", "a80bb13607492a8c5d2108b23db532ba"),
        ("0x20", "a80bb13607492a8c5d2108b23db532ba"),  # Real-time interactive
    ]
    for value, expected_checksum in values:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip6 -c {value}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip6_ecn_field():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    values = [
        # From RFC 3168
        # ECN: Explicit Congestion Notification
        # ECT: ECN-Capable Transport
        # CE: Congestion Experienced
        # To set ECN field, choose one of the 4 codepoints below:
        # ----------------------------------
        #             ECN FIELD
        # ----------------------------------
        # ECT  CE  Hex value  Codepoint name
        # ----------------------------------
        # 0    0   0x00       Not-ECT
        # 0    1   0x01       ECT(1)
        # 1    0   0x02       ECT(0)
        # 1    1   0x03       CE
        # ----------------------------------
        ("0", "fd907f31094c4937012285acf200e28f"),
        ("0x00", "fd907f31094c4937012285acf200e28f"),  # 0b00000011 Not-ECT
        ("1", "30f782ab4c0d12ad7ab5e9cc1b00de8e"),
        ("0x01", "30f782ab4c0d12ad7ab5e9cc1b00de8e"),  # 0b00000001 ECT(1)
        ("2", "f4d7480a83ddd35de40a3224be44b07a"),
        ("0x02", "f4d7480a83ddd35de40a3224be44b07a"),  # 0b00000010 ECT(0)
        ("3", "e6aa1806cb7f3b7df354570e5ebd4d81"),
        ("0x03", "e6aa1806cb7f3b7df354570e5ebd4d81"),  # 0b00000011 CE
    ]
    for value, expected_checksum in values:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip6 -e {value}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip6_flow_label():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    in_checksum = hashlib.md5(open(in_pcap_file, "rb").read()).hexdigest()
    flow_labels = [
        # 217523, 0x351b3, 0x0351b3, and 0650663 are all equal but specified in
        # different notation.
        ("217523", in_checksum),  # integer input
        ("0x351b3", in_checksum),  # hexadecimal input, leading 0x
        ("0x0351b3", in_checksum),  # hexadecimal input, leading 0x
        ("0650663", in_checksum),  # octal input, leading 0
        ("0x00000", "e426a6627f85ec9e81c92aba38c82809"),
        ("0", "e426a6627f85ec9e81c92aba38c82809"),
        ("0xfffff", "d46873fcd066f82302169e52bd235247"),
        ("1048575", "d46873fcd066f82302169e52bd235247"),
    ]
    for flow_label, expected_checksum in flow_labels:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip6 -f {flow_label}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip6_hop_limit():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    hop_limits = [
        ("0", "e3b0d298d4f3f994674b50dd69e9fdc5"),
        ("255", "e18371eabf1e0eff127feed105f256af"),
    ]
    for hop_limit, expected_checksum in hop_limits:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip6 -h {hop_limit}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_ip6_sip():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip6 -s fd00::1"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "2945d7bf35e49e9d1370f43387b9e74e"


def test_bittwiste_ip6_dip():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T ip6 -d fd00::2"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "a47dd221b2a8a9c20433d80b20a32a97"


def test_bittwiste_icmp_type():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T icmp -t 0"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "decdb8f44253801bcfdc845387d6f6cb"


def test_bittwiste_icmp_code():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T icmp -c 255"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "aef78c21afb648a5c554bd2256dc6389"


def test_bittwiste_icmp6_type():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp6.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T icmp6 -t 129"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "2458130f660da7acf73e984bfc2d858b"


def test_bittwiste_icmp6_code():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "icmp6.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T icmp6 -c 255"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "5690afe231cd89d2a0b6dde31d1b6441"


def test_bittwiste_tcp_sport():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    opts = [
        ("-T tcp -s 1000", "b064417c556ef7a068f7cda4c1aa0865"),
        ("-T tcp -s 30000,1000", "b064417c556ef7a068f7cda4c1aa0865"),
        ("-P 10000 -T tcp -s rand", "4ff6f9931fc2e0b7065eb613e5bd7a2a"),
        ("-P 10000 -T tcp -s 30000,rand", "4ff6f9931fc2e0b7065eb613e5bd7a2a"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_tcp_dport():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    opts = [
        ("-T tcp -d 1000", "f6f4d2431303b49c47d7e3a63178e2ff"),
        ("-T tcp -d 60000,1000", "f6f4d2431303b49c47d7e3a63178e2ff"),
        ("-P 10000 -T tcp -d rand", "737aae1e41f76e323da89ebb3df86dd7"),
        ("-P 10000 -T tcp -d 60000,rand", "737aae1e41f76e323da89ebb3df86dd7"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_tcp_seq():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp.pcap"
    opts = [
        ("-T tcp -q 0", "eab1ff9e93ada77cd598b1173fbd1e36"),
        ("-T tcp -q 4294967295", "c7dfbf484ecc6cabe6e2d7aa7db502fc"),
        ("-T tcp -q 2053058830,100", "e46cc50cb4c4159692b62deb09be511e"),
        ("-P 10000 -T tcp -q rand", "a21d1ae3d7dd4b5fae9c8dac9dd75c77"),
        ("-P 10000 -T tcp -q 2053058831,rand", "857cc97740470d7995c2fb7e9bb80374"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_tcp_ack():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp.pcap"
    opts = [
        ("-T tcp -a 0", "5b57c547f994a80dd284c176dfaade3e"),
        ("-T tcp -a 4294967295", "0b7f0b0b502f93e818cab70f147de02c"),
        ("-T tcp -a 0,100", "13e5873d42f2115a2a5dae4b2a78bf4a"),
        ("-P 10000 -T tcp -a rand", "ebbf176a8ec144e8e84b6ee0aa54561f"),
        ("-P 10000 -T tcp -a 143840249,rand", "e304ecb1942c875a8d73db1da7aeb9be"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_tcp_flags():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp.pcap"
    flags = [
        ("-", "5a62552112078b48e578909c8829a0bd"),
        ("c", "e512b62c0fd8ddb0084afddc0a1df163"),
        ("e", "a9e39e786441ddfb894437e4ca31cd03"),
        ("u", "90148eeee21504b0452fc074b033e828"),
        ("a", "9c171b01791a089c6d8896462a86a313"),
        ("p", "eb86309a48eeb86695cbc7ab124d50b3"),
        ("r", "74edf982a1b3bd504f2c7fb808040398"),
        ("s", "bffdb416fa9f142d5a5ab73668d051f5"),
        ("f", "58da6f385414ce1fdb7e9c0cfa1becf1"),
        ("ceuaprsf", "bd002c3a6fa2bf65f612c6c65063ba80"),
    ]
    for flag, expected_checksum in flags:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T tcp -f {flag}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_tcp_win():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T tcp -w 65535"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "77e7eccd00e2e58915d9ce66771c5892"


def test_bittwiste_tcp_urg():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "tcp6.pcap"
    command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} -T tcp -u 65535"
    subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

    out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
    assert out_checksum == "f7c30cad1c6eca1a949e2a02bbeb3fb7"


def test_bittwiste_udp_sport():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp.pcap"
    opts = [
        ("-T udp -s 0", "f40f2330d6c7a5c6b912820fc75c520f"),
        ("-T udp -s 60935,0", "f40f2330d6c7a5c6b912820fc75c520f"),
        ("-P 10000 -T udp -s rand", "00235742347dc989f273bef864c15413"),
        ("-P 10000 -T udp -s 60935,rand", "00235742347dc989f273bef864c15413"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum


def test_bittwiste_udp_dport():
    in_pcap_file = Path(__file__).resolve().parent / "pcap" / "udp6.pcap"
    opts = [
        ("-T udp -d 65535", "e9875fa4b2f6f14f21335c1b3e84d7ec"),
        ("-T udp -d 53,65535", "e9875fa4b2f6f14f21335c1b3e84d7ec"),
        ("-P 10000 -T udp -d rand", "66d4781d2f88aadbb12416c398f34886"),
        ("-P 10000 -T udp -d 53,rand", "66d4781d2f88aadbb12416c398f34886"),
    ]
    for opt, expected_checksum in opts:
        command = f"{bin} -I {in_pcap_file} -O {out_pcap_file} {opt}"
        subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT)

        out_checksum = hashlib.md5(open(out_pcap_file, "rb").read()).hexdigest()
        assert out_checksum == expected_checksum
