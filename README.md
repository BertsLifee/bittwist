# Bit-Twist: Libpcap-based Ethernet packet generator

SPDX-License-Identifier: GPL-2.0-or-later

Supported systems: Linux, BSD, macOS, and Windows.

Bit-Twist is a simple yet powerful libpcap-based Ethernet packet generator and
packet editor. It is designed to complement tcpdump, which by itself has done a
great job at capturing network traffic.

> With Bit-Twist, you can now regenerate your captured traffic onto a live
> network! Packets are generated from tcpdump trace file (.pcap file).
> Bit-Twist also comes with a comprehensive trace file editor to allow you to
> change the contents of a trace file.

> Bit-Twist is designed for exceptional speed! Utilizing a standard laptop with
> Linux system, you can edit **10 million packets in less than 5 seconds**, and
> send the packets onto a live network, achieving throughput levels that match
> the maximum line rate of your NIC.

Packet generator is useful in simulating networking traffic or scenario,
testing firewall, IDS, and IPS, and troubleshooting various network problems.

## Features

These are just a few significant features that makes Bit-Twist unique and
stands out as one of the best Ethernet packet generator and packet editor
package made available to the open source community.

- Highly portable: Bit-Twist runs on Linux, BSD, macOS, and Windows.

- Send multiple trace files indefinitely with set interval, packets per second,
  or line rate between 1 Mbps to 10 Gbps using built-in token bucket algorithm.

- Comprehensive trace file editor to edit most fields in Ethernet, ARP, IPv4,
  IPv6, ICMPv4, ICMPv6, TCP, and UDP headers. Templates are also included to
  generate packets with these headers without needing an existing trace file.

- Automatic header checksum correction (with option to disable).

- Send packets with custom QoS bits to test classification and queuing features
  of switches and routers.

- Send packets with uniformly distributed random numbers for port numbers,
  TCP sequence numbers, etc.

- Append custom payload (e.g. copy of hex stream from Wireshark) to existing
  packets after a specific header, handy for testing new protocols.

- Send packets with truncated or expanded length in bytes, facilitating
  incremental throughput testing.

- Highly scriptable: With proper manipulation, you can turn Bit-Twist into a
  versatile packet generator and packet editor tooling to meet your network
  testing requirements.

For the complete feature list, see Bit-Twist man pages:

- [bittwist.1](https://bittwist.sourceforge.io/doc/bittwist.1.html) - pcap based ethernet packet generator
- [bittwiste.1](https://bittwist.sourceforge.io/doc/bittwiste.1.html) - pcap capture file editor

## Examples

Please visit https://bittwist.sourceforge.io/doc.html for examples on how to
use Bit-Twist.

## Installation

Follow the instructions for your operating system below to install, run, or
build Bit-Twist on your machine.

Unless specified otherwise:

- executables (bittwist, bittwiste) are installed in /usr/local/bin
- manual pages (bittwist.1, bittwiste.1) are installed in /usr/local/share/man/man1

For more general information, please visit https://bittwist.sourceforge.io

## For Windows systems

This distribution is tested to work on Microsoft Windows 10.

### Installation

- Download Npcap installer from https://npcap.com/dist/npcap-1.75.exe

- Run the Npcap installer to install Npcap on your system.
  Select "Install Npcap in WinPcap API-compatible Mode" option during the
  installation.

- Extract bittwist-windows-3.8.zip into C:\Users\_YOUR_USERNAME_\Downloads

- In Command Prompt:

```
> cd C:\Users\_YOUR_USERNAME_\Downloads\bittwist-windows-3.8\src
> bittwist -h   (usage for packet generator)
> bittwiste -h  (usage for packet editor)
> bittwist -d   (to view available network cards you can send packets on)
```

- You may readily use Bit-Twist from the src directory as above.

- If you wish to install Bit-Twist system-wide, copy the files from src
  directory into C:\WINDOWS\system32:
  - bittwist.exe
  - bittwist.exe
  - cygwin1.dll (From https://www.cygwin.com)

- Manual pages are available in doc/

### Recompilation

This distribution is compiled against Npcap 1.75 with Npcap SDK 1.13 in
Cygwin environment on Microsoft Windows 10.

If you wish to rebuild Bit-Twist from source files, you will need Cygwin
environment:

- Download Cygwin installer from https://www.cygwin.com/setup-x86_64.exe

- Run the Cygwin installer to install Cygwin environment on your system.

- Be sure to select at least the following packages in the
  "Cygwin Setup - Select Packages" window:
  - Devel > gcc-core
  - Devel > make
  - Devel > binutils 2.38-1 (newer version may not work yet)
  - Devel > mingw64-x86_64-binutils 2.38-1 (newer version may not work yet)

- Click on the "Cygwin64 Terminal" icon in your desktop to launch a new
  terminal under Cygwin environment.

```
$ cd /cygdrive/c/Users/_YOUR_USERNAME_/Downloads/bittwist-windows-3.8
$ make
$ make install
$ bittwist -h   (usage for packet generator)
$ bittwiste -h  (usage for packet editor)
$ bittwist -d   (to view available network cards you can send packets on)
```

## For Linux systems

This distribution is tested to work on CentOS Stream 9.

### Required dependencies

- Libpcap is required (available for download from https://www.tcpdump.org/).
  This distribution is compiled against libpcap 1.10.4.
  Sample installation of libpcap 1.10.4 on CentOS Stream 9:

```
$ sudo yum install make gcc flex bison
$ wget https://www.tcpdump.org/release/libpcap-1.10.4.tar.gz
$ tar -xzf libpcap-1.10.4.tar.gz
$ cd libpcap-1.10.4
$ ./configure && make && sudo make install
$ sudo ldconfig
```

### Installation

```
$ tar -xzf bittwist-linux-3.8.tar.gz
$ cd bittwist-linux-3.8
$ make
$ sudo make install
```

## For macOS systems

This distribution is tested to work on macOS Ventura 13.3.1

### Required dependencies

- Libpcap is required (available for download from https://www.tcpdump.org/).
  This distribution is compiled against libpcap 1.10.4. However, any existing
  libpcap on your system may work normally with Bit-Twist.

- Xcode command line developer tools; you will be prompted to install this
  automatically on your first attempt to run make below.

### Installation

```
$ tar -xzf bittwist-macos-3.8.tar.gz
$ cd bittwist-macos-3.8
$ make
$ sudo make install
```

## For BSD systems

This distribution is tested to work on FreeBSD 13.2-RELEASE.

### Required dependencies

- Libpcap is required (available for download from https://www.tcpdump.org/).
  This distribution is compiled against libpcap 1.10.4. However, any existing
  libpcap on your system may work normally with Bit-Twist.

### Installation

```
$ tar -xzf bittwist-bsd-3.8.tar.gz
$ cd bittwist-bsd-3.8
$ make
$ sudo make install
```
