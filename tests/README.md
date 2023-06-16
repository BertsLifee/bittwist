# Bit-Twist Python testing framework

This framework is targeted for Linux systems to:
- Validate packet generation between release and development version.
- Benchmark large packet generation between release and development version.
- Run tests for development version of bittwist and bittwiste.

## Setup

```
$ ~/.pyenv/versions/3.11.3/bin/python -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
```

## Running tests

Ensure ../src/bittwist and ../src/bittwiste has been built successfully prior to running tests.
Some tests (../src/bittwist) will perform actual packet injection, so sudo is required.

To run all available tests (sudo is required):

```
./test.sh
```

To run tests for ../src/bittwist (sudo is required):

```
pytest test_bittwist.py
```

To run tests for ../src/bittwiste:

```
pytest test_bittwiste.py
```

To run specific test:

```
pytest test_bittwiste.py::test_bittwiste_copy
```

## bittwist baseline benchmark

Use iperf to measure initial localhost througput on your system.

Server terminal:
```
$ iperf -s -e -i 1 -l 1500
```

Client terminal:
```
$ iperf -c 127.0.0.1 -e -i 1
```

Compare iperf throughput vs throughput from test_bittwist.py::test_bittwist_2M_speed when running test.sh above.
The difference should be less than 15%.

## bittwiste benchmark

Result: Edit 10 million IP packets in 4 seconds.

Method:
```
# Run the test.sh separately to generate packets to be captured.
$ sudo tcpdump -i lo -w 10M.pcap -c 10000000 -v -n -B 65536 -Z "$(whoami)" 'tcp port 0'

# 15GB of 10 million packets captured.
$ du -h 10M.pcap
15G  10M.pcap

# Inspect first few captured packets.
$ tcpdump -v -r 10M.pcap -c 2
reading from file 10M.pcap, link-type EN10MB (Ethernet), snapshot length 262144
15:07:55.832237 IP (tos 0x0, ttl 64, id 12930, offset 0, flags [DF], proto TCP (6), length 1500)
    localhost.0 > localhost.0:  tcp 1480 [bad hdr length 0 - too short, < 20]
15:07:55.832246 IP (tos 0x0, ttl 64, id 12930, offset 0, flags [DF], proto TCP (6), length 1500)
    localhost.0 > localhost.0:  tcp 1480 [bad hdr length 0 - too short, < 20]

# Run bittwiste to edit pcap to save up to layer 3 only (IP).
$ time bittwiste -I 10M.pcap -O 10M.ip.pcap -L 3
input file: 10M.pcap
output file: 10M.ip.pcap

10000000 packets (500000024 bytes) written

real  0m4.276s
user  0m2.389s
sys   0m1.888s

# Inspect first few edited packets.
$ tcpdump -v -r 10M.ip.pcap -c 2
reading from file 10M.ip.pcap, link-type EN10MB (Ethernet), snapshot length 262144
15:07:55.832237 IP (tos 0x0, ttl 64, id 12930, offset 0, flags [DF], proto TCP (6), length 20)
    localhost > localhost: [|tcp]
15:07:55.832246 IP (tos 0x0, ttl 64, id 12930, offset 0, flags [DF], proto TCP (6), length 20)
    localhost > localhost: [|tcp]
```
