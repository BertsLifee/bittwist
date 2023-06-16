#!/bin/bash
# Use this script to perform checkout test for newly installed version of Bit-Twist.
# Checkout test is done manually prior to public release.

read -p "src_mac: " src_mac
read -p "dst_mac: " dst_mac

read -p "src_ip: " src_ip
read -p "dst_ip: " dst_ip

# 1. Create ICMP echo request packet with correct addresses:
bittwiste -I icmp -O 1.pcap -L 4 -X $(printf '0%.0s' $(seq 1 3000)) -T icmp
bittwiste -I 1.pcap -O 2.pcap -T eth -s ${src_mac} -d ${dst_mac}
bittwiste -I 2.pcap -O 3.pcap -T ip -s ${src_ip} -d ${dst_ip}

# 2. Send edited packet at 1 Mbps:
sudo bittwist -i 1 -l 0 -r 1 3.pcap

# 3. Monitor traffic at destination:
# sudo tcpdump -i 1 -n 'icmp'

rm -f 1.pcap 2.pcap 3.pcap
