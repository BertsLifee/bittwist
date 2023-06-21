/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * bittwiste - pcap capture file editor
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

#include "bittwiste.h"
#include "template_pcap.h"
#include "tinymt64.h"

char *program_name;

/* general options */
int header_opt = -1; /* specifies which header to edit, -1 -> no header selected */
int layer_opt = 0;   /* copy up to the specified layer only */
int start_oset_opt = 0, end_oset_opt = 0;  /* delete the specified byte offset */
int start_opt = 0, end_opt = 0;            /* copy the specified range of packets only */
time_t start_sec_opt = 0, end_sec_opt = 0; /* copy packets within the specified timeframe only */
uint32_t gap_start_opt, gap_end_opt;       /* inter-packet gap range in microseconds (inclusive) */
struct pcap_timeval gap_last_ts = {0, 0};  /* track last timestamp when applying custom gap */
int repeat_opt = 0;                        /* duplicate packets for the specified times */

int csum_opt = 1;             /* set to 0 to disable checksum correction */
uint8_t *payload_opt = NULL;  /* payload in hex digits *NOTFREED* */
uint16_t payload_len_opt = 0; /* length of payload in bytes */
int linktype_opt = -1;        /* pcap preamble link type field, -1 -> no override */

bool nsec = false; /* set to true if we have timestamps in nanosecond resolution */

/* TinyMT as random number generator (RNG) */
tinymt64_t tinymt;

/* header specific options *NOTFREED* */
struct ethopt *ethopt;     /* Ethernet options */
struct arpopt *arpopt;     /* ARP options */
struct ipopt *ipopt;       /* IP options */
struct ip6opt *ip6opt;     /* IPv6 options */
struct icmpopt *icmpopt;   /* ICMP options */
struct icmp6opt *icmp6opt; /* ICMPv6 options */
struct tcpopt *tcpopt;     /* TCP options */
struct udpopt *udpopt;     /* UDP options */

/* stats */
static unsigned long pkts = 0;
static unsigned long bytes = 0;

int main(int argc, char **argv)
{
    char *cp;
    int c, i;
    char *str = NULL;
    char *infile = NULL;
    char *outfile = NULL;
    struct tm *tm = NULL;

    /* use current time as default seed for RNG, can be optionally set using -P flag */
    unsigned int seed = time(NULL);

    if ((cp = strrchr(argv[0], '/')) != NULL)
        program_name = cp + 1;
    else
        program_name = argv[0];

    /* process general options */
    while ((c = getopt(argc, argv, "I:O:L:X:CM:D:R:S:N:G:P:T:h")) != -1)
    {
        switch (c)
        {
        case 'I':
            infile = optarg; /* file path or template name */
            break;
        case 'O':
            outfile = optarg;
            break;
        case 'L':
            layer_opt = strtol(optarg, NULL, 0);
            /*
             * 2 - Ethernet
             * 3 - ARP, IP
             * 4 - ICMP, TCP, UDP
             */
            if (layer_opt < 2 || layer_opt > 4)
                error("layer is out of range");
            break;
        case 'X': /* ignored if option -L and -T are not specified */
            c = strlen(optarg);
            if (c > (PAYLOAD_MAX * 2) || (c % 2) != 0)
                error("invalid payload specification");
            payload_len_opt = c / 2;
            payload_opt = (uint8_t *)malloc(sizeof(uint8_t) * payload_len_opt);
            if (payload_opt == NULL)
                error("malloc(): cannot allocate memory for payload_opt");
            /* make a byte of data from every 2 characters of optarg */
            for (i = 0; i < payload_len_opt; i++)
            {
                uint8_t hex_byte[3] = {optarg[i * 2], optarg[i * 2 + 1], '\0'};
                if (!isxdigit(hex_byte[0]) || !isxdigit(hex_byte[1]))
                    error("invalid payload specification");
                sscanf((char *)hex_byte, "%hhx", &payload_opt[i]);
            }
            break;
        case 'C':
            csum_opt = 0; /* DISABLE checksum correction */
            break;
        case 'M':
            linktype_opt = strtol(optarg, NULL, 0);
            /*
             * 1 - Ethernet
             * 9 - PPP
             * 12 - Raw IP
             * 51 - PPPoE
             * 105 - IEEE 802.11 wireless
             * 117 - OpenBSD pflog
             * 118 - Cisco IOS
             * 119 - 802.11 with Prism hdr
             */
            if (linktype_opt < 0 || linktype_opt > UCHAR_MAX)
                error("linktype is out of range");
            break;
        case 'D':
            /*
             * -D 15-18, delete from byte 15th through byte 18th (inclusive),
             * starting from link-layer hdr
             */
            str = strdup(optarg);
            if (str == NULL)
                error("strdup(): cannot allocate memory for str");
            if ((cp = (char *)strtok(str, "-")) == NULL)
                error("invalid offset specification");
            start_oset_opt = strtol(cp, NULL, 0);
            if ((cp = (char *)strtok(NULL, "-")) == NULL)
                end_oset_opt = start_oset_opt; /* delete a single byte, e.g. -D 15 */
            else
                end_oset_opt = strtol(cp, NULL, 0);
            free(str);
            str = NULL;
            if (start_oset_opt <= 0 || end_oset_opt <= 0 || (start_oset_opt > end_oset_opt))
                error("invalid offset specification");
            break;
        case 'R': /* e.g. -R 5-21 or -R 9 */
            str = strdup(optarg);
            if (str == NULL)
                error("strdup(): cannot allocate memory for str");
            if ((cp = (char *)strtok(str, "-")) == NULL)
                error("invalid range specification");
            start_opt = strtol(cp, NULL, 0);
            if ((cp = (char *)strtok(NULL, "-")) == NULL)
                end_opt = start_opt; /* only one packet */
            else
                end_opt = strtol(cp, NULL, 0);
            free(str);
            str = NULL;
            if (start_opt <= 0 || end_opt <= 0 || (start_opt > end_opt))
                error("invalid range specification");
            break;
        case 'S':
            /*
             * time frame with one-second resolution: -S 22/10/2006,21:47:35-24/10/2006,13:16:05
             * format: -S DD/MM/YYYY,HH:MM:SS-DD/MM/YYYY,HH:MM:SS
             * note that -S 22/10/2006-24/10/2006 is equivalent to -S
             * 22/10/2006,00:00:00-24/10/2006,00:00:00
             */
            str = strdup(optarg);
            if (str == NULL)
                error("strdup(): cannot allocate memory for str");
            if ((cp = (char *)strtok(str, "-")) == NULL)
                error("invalid timeframe specification");
            tm = (struct tm *)malloc(sizeof(struct tm));
            if (tm == NULL)
                error("malloc(): cannot allocate memory for tm");
            if (!strptime(cp, "%d/%m/%Y,%T", tm))
                error("invalid timeframe specification");
            start_sec_opt = mktime(tm);
            if ((cp = (char *)strtok(NULL, "-")) == NULL)
                end_sec_opt = start_sec_opt; /* only the packets within the one-second resolution */
            else
            {
                if (!strptime(cp, "%d/%m/%Y,%T", tm))
                    error("invalid timeframe specification");
            }
            end_sec_opt = mktime(tm);
            free(tm);
            tm = NULL;
            free(str);
            str = NULL;
            if (start_sec_opt > end_sec_opt)
                error("invalid timeframe specification");
            break;
        case 'N': /* e.g. -N 10, duplicate packet for 10 times */
            repeat_opt = strtol(optarg, NULL, 0);
            if (repeat_opt < 0)
                error("invalid repeat specification");
            break;
        case 'G': /* inter-packet gap in microseconds, e.g. -G 1000-10000 or -G 1000 */
            str = strdup(optarg);
            if (str == NULL)
                error("strdup(): cannot allocate memory for str");
            if ((cp = (char *)strtok(str, "-")) == NULL)
                error("invalid gap range specification");
            gap_start_opt = strtol(cp, NULL, 0);
            if ((cp = (char *)strtok(NULL, "-")) == NULL)
                gap_end_opt = gap_start_opt; /* fixed gap */
            else
                gap_end_opt = strtol(cp, NULL, 0); /* ranged random gap */
            free(str);
            str = NULL;
            if (gap_start_opt <= 0 || gap_end_opt <= 0 || gap_start_opt > INT32_MAX ||
                gap_end_opt > INT32_MAX || (gap_start_opt > gap_end_opt))
                error("invalid gap range specification");
            gap_last_ts.tv_sec = GAP_START;
            break;
        case 'P': /* optional positive integer to seed RNG */
            seed = strtol(optarg, NULL, 0);
            if (seed < 0)
                error("invalid seed specification");
            break;
        case 'T':
            if (strcasecmp(optarg, "eth") == 0)
                header_opt = ETH;
            else if (strcasecmp(optarg, "arp") == 0)
                header_opt = ARP;
            else if (strcasecmp(optarg, "ip") == 0)
                header_opt = IP;
            else if (strcasecmp(optarg, "ip6") == 0)
                header_opt = IP6;
            else if (strcasecmp(optarg, "icmp") == 0)
                header_opt = ICMP;
            else if (strcasecmp(optarg, "icmp6") == 0)
                header_opt = ICMP6;
            else if (strcasecmp(optarg, "tcp") == 0)
                header_opt = TCP;
            else if (strcasecmp(optarg, "udp") == 0)
                header_opt = UDP;
            else
                error("invalid header specification");
            /* process hdr specific options */
            parse_header_options(argc, argv);
            break;
        case 'h':
        default:
            usage();
        }
    }

    if (infile == NULL)
        error("input file not specified");

    if (outfile == NULL)
        error("output file not specified");

    if (strcmp(infile, outfile) == 0)
        error("invalid outfile specification");

    /* initialize RNG */
    tinymt64_init(&tinymt, seed);

    parse_trace(infile, outfile);

    info();
    exit(EXIT_SUCCESS);
}

void set_eth_addr_options(char *optarg, struct eth_addr_opt *opt)
{
    /*
     * optarg:
     * - 11:11:11:11:11:11 (overwrite MAC), flag = FIELD_SET
     * - 11:11:11:11:11:11,22:22:22:22:22:22 (overwrite matching MAC), flag = FIELD_REPLACE
     * - rand (overwrite MAC with random MAC), flag = FIELD_SET_RAND
     * - 11:11:11:11:11:11,rand (overwrite matching MAC with random MAC), flag = FIELD_REPLACE_RAND
     */
    char *str = strdup(optarg);
    if (str == NULL)
        error("strdup(): cannot allocate memory for str");

    char *cp = strtok(str, ",");
    if (cp == NULL)
        error("invalid MAC address");

    if (strcasecmp(cp, "rand") == 0)
        opt->flag = FIELD_SET_RAND; /* overwrite MAC with random MAC */
    else
    {
        if (eth_aton(cp, opt->old) != 1)
            error("invalid MAC address");

        cp = strtok(NULL, ",");
        if (cp == NULL)
            opt->flag = FIELD_SET; /* overwrite MAC */
        else if (strcasecmp(cp, "rand") == 0)
            opt->flag = FIELD_REPLACE_RAND; /* overwrite matching MAC with random MAC */
        else
        {
            opt->flag = FIELD_REPLACE; /* overwrite matching MAC */
            if (eth_aton(cp, opt->new) != 1)
                error("invalid MAC address");
        }
    }

    free(str);
}

void set_rand_in_addr_options(char *cp, struct in_addr *netnum, struct in_addr *netmask,
                              uint8_t *rand_bits)
{
    uint8_t netlen;

    /*
     * parse CIDR notation in the form of <network number>/<prefix length>, e.g. 1.0.0.0/8
     * 0.0.0.0/0 will result in random IPv4 selected from the entire range
     */
    char *input_netnum = strtok(cp, "/");
    char *input_netlen = strtok(NULL, "/");

    if (input_netnum == NULL || input_netlen == NULL)
        error("invalid CIDR notation");

    if (inet_pton(AF_INET, input_netnum, netnum) != 1)
        error("invalid CIDR notation");

    /* extract prefix length to calculate netmask */
    netlen = atoi(input_netlen);
    if (netlen < 0 || netlen > 32)
        error("invalid CIDR notation");

    /* number of bits available to the right that can be randomized */
    *rand_bits = 32 - netlen;

    /* calculate network mask and update the network number */
    if (netlen == 0)
        netmask->s_addr = 0; /* special handling for /0 */
    else
    {
        netmask->s_addr = htonl((uint32_t)(0xffffffffu << (32 - netlen)));
        if (netnum->s_addr != (netnum->s_addr & netmask->s_addr))
            netnum->s_addr &= netmask->s_addr;
    }
}

void set_in_addr_options(char *optarg, struct in_addr_opt *opt)
{
    /*
     * optarg:
     * - 1.1.1.1 (overwrite IP), flag = FIELD_SET
     * - 1.1.1.1,2.2.2.2 (overwrite matching IP), flag = FIELD_REPLACE
     * - 1.0.0.0/8 (overwrite IP with IP from CIDR), flag = FIELD_SET_RAND
     * - 1.1.1.1,2.0.0.0/8 (overwrite matching IP with IP from CIDR), flag = FIELD_REPLACE_RAND
     */
    char *str = strdup(optarg);
    if (str == NULL)
        error("strdup(): cannot allocate memory for str");

    char *cp = strtok(str, ",");
    if (cp == NULL)
        error("invalid IPv4 address");

    if (strstr(cp, "/") != NULL && strchr(cp, ',') == NULL)
    {
        opt->flag = FIELD_SET_RAND; /* overwrite IP with IP from CIDR */
        set_rand_in_addr_options(cp, &opt->new, &opt->netmask, &opt->rand_bits);
    }
    else
    {
        if (inet_pton(AF_INET, cp, &opt->old) != 1)
            error("invalid IPv4 address");

        cp = strtok(NULL, ",");
        if (cp == NULL)
            opt->flag = FIELD_SET; /* overwrite IP */
        else if (strstr(cp, "/") != NULL && strchr(cp, ',') == NULL)
        {
            opt->flag = FIELD_REPLACE_RAND; /* overwrite matching IP with IP from CIDR */
            set_rand_in_addr_options(cp, &opt->new, &opt->netmask, &opt->rand_bits);
        }
        else
        {
            opt->flag = FIELD_REPLACE; /* overwrite matching IP */
            if (inet_pton(AF_INET, cp, &opt->new) != 1)
                error("invalid IPv4 address");
        }
    }

    free(str);
}

void set_rand_in6_addr_options(char *cp, struct in6_addr *netnum, struct in6_addr *netmask,
                               uint8_t *rand_bits)
{
    uint8_t netlen, shift, i, s;

    /*
     * parse CIDR notation in the form of <network number>/<prefix length>, e.g. 2001:db8::/48
     * ::/0 will result in random IPv6 selected from the entire range
     */
    char *input_netnum = strtok(cp, "/");
    char *input_netlen = strtok(NULL, "/");

    if (input_netnum == NULL || input_netlen == NULL)
        error("invalid CIDR notation");

    if (inet_pton(AF_INET6, input_netnum, netnum) != 1)
        error("invalid CIDR notation");

    /* extract prefix length to calculate netmask */
    netlen = atoi(input_netlen);
    if (netlen < 0 || netlen > 128)
        error("invalid CIDR notation");

    /* number of bits available to the right that can be randomized */
    *rand_bits = 128 - netlen;

    /* calculate network mask and update the network number */
    shift = netlen;
    for (i = 0; i < 16; i++) /* 16 octets in IPv6 */
    {
        s = (shift > 8) ? 8 : shift;
        shift -= s;
        netmask->s6_addr[i] = (uint8_t)(0xffu << (8 - s));
        if (netnum->s6_addr[i] != (netnum->s6_addr[i] & netmask->s6_addr[i]))
            netnum->s6_addr[i] &= netmask->s6_addr[i];
    }
}

void set_in6_addr_options(char *optarg, struct in6_addr_opt *opt)
{
    /*
     * optarg:
     * - ::1 (overwrite IP), flag = FIELD_SET
     * - ::1,::2 (overwrite matching IP), flag = FIELD_REPLACE
     * - ::2/64 (overwrite IP with IP from CIDR), flag = FIELD_SET_RAND
     * - ::1,::2/64 (overwrite matching IP with IP from CIDR), flag = FIELD_REPLACE_RAND
     */
    char *str = strdup(optarg);
    if (str == NULL)
        error("strdup(): cannot allocate memory for str");

    char *cp = strtok(str, ",");
    if (cp == NULL)
        error("invalid IPv6 address");

    if (strstr(cp, "/") != NULL && strchr(cp, ',') == NULL)
    {
        opt->flag = FIELD_SET_RAND; /* overwrite IP with IP from CIDR */
        set_rand_in6_addr_options(cp, &opt->new, &opt->netmask, &opt->rand_bits);
    }
    else
    {
        if (inet_pton(AF_INET6, cp, &opt->old) != 1)
            error("invalid IPv6 address");

        cp = strtok(NULL, ",");
        if (cp == NULL)
            opt->flag = FIELD_SET; /* overwrite IP */
        else if (strstr(cp, "/") != NULL && strchr(cp, ',') == NULL)
        {
            opt->flag = FIELD_REPLACE_RAND; /* overwrite matching IP with IP from CIDR */
            set_rand_in6_addr_options(cp, &opt->new, &opt->netmask, &opt->rand_bits);
        }
        else
        {
            opt->flag = FIELD_REPLACE; /* overwrite matching IP */
            if (inet_pton(AF_INET6, cp, &opt->new) != 1)
                error("invalid IPv6 address");
        }
    }

    free(str);
}

void set_number_options(char *optarg, void *val_a, void *val_b, uint8_t *flag, size_t val_size)
{
    /*
     * optarg:
     * - 1 (overwrite value), flag = FIELD_SET
     * - 1,2 (overwrite matching value), flag = FIELD_REPLACE
     * - rand (overwrite value with random value), flag = FIELD_SET_RAND
     * - 1,rand (overwrite matching value with random value), flag = FIELD_REPLACE_RAND
     */
    char *str = strdup(optarg);
    if (str == NULL)
        error("strdup(): cannot allocate memory for str");

    char *cp = strtok(str, ",");
    if (cp == NULL)
        error("invalid number specification");

    if (strcasecmp(cp, "rand") == 0)
        *flag = FIELD_SET_RAND; /* overwrite value with random value */
    else
    {
        /* input value can be integer, hexadecimal, or octal */
        uint64_t v = strtoul(cp, NULL, 0);

        /*
         * accept sizeof(uint8_t) for e.g. protocol number
         * accept sizeof(uint16_t) for e.g. tcp port number
         * accept sizeof(uint32_t) for e.g. tcp sequence number
         */
        uint32_t max_val;
        if (val_size == sizeof(uint8_t))
            max_val = UINT8_MAX;
        else if (val_size == sizeof(uint16_t))
            max_val = UINT16_MAX;
        else
            max_val = UINT32_MAX;

        if (v < 0 || v > max_val)
            error("number is out of range: %lu", v);

        if (val_size == sizeof(uint8_t))
            *((uint8_t *)val_a) = (uint8_t)v;
        else if (val_size == sizeof(uint16_t))
            *((uint16_t *)val_a) = (uint16_t)v;
        else
            *((uint32_t *)val_a) = (uint32_t)v;

        cp = strtok(NULL, ",");
        if (cp == NULL)
            *flag = FIELD_SET; /* overwrite value */
        else if (strcasecmp(cp, "rand") == 0)
            *flag = FIELD_REPLACE_RAND; /* overwrite matching value with random value */
        else
        {
            v = strtoul(cp, NULL, 0);
            if (v < 0 || v > max_val)
                error("number is out of range: %lu", v);

            if (val_size == sizeof(uint8_t))
                *((uint8_t *)val_b) = (uint8_t)v;
            else if (val_size == sizeof(uint16_t))
                *((uint16_t *)val_b) = (uint16_t)v;
            else
                *((uint32_t *)val_b) = (uint32_t)v;

            *flag = FIELD_REPLACE; /* overwrite matching value */
        }
    }

    free(str);
}

void parse_header_options(int argc, char **argv)
{
    char *cp;
    int c;
    char *str = NULL;
    uint32_t v; /* input value (can be integer, hexadecimal, or octal) returned by strtol */

    if (header_opt == ETH)
    {
        ethopt = (struct ethopt *)malloc(sizeof(struct ethopt));
        if (ethopt == NULL)
            error("malloc(): cannot allocate memory for ethopt");
        memset(ethopt, 0, sizeof(struct ethopt));
        while ((c = getopt(argc, argv, "d:s:t:")) != -1)
        {
            switch (c)
            {
            case 'd': /* destination MAC */
                set_eth_addr_options(optarg, &ethopt->dhost);
                break;
            case 's': /* source MAC */
                set_eth_addr_options(optarg, &ethopt->shost);
                break;
            case 't': /* type */
                if (strcasecmp(optarg, "ip") == 0)
                    ethopt->eth_type = ETH_TYPE_IP;
                else if (strcasecmp(optarg, "ip6") == 0)
                    ethopt->eth_type = ETH_TYPE_IPV6;
                else if (strcasecmp(optarg, "arp") == 0)
                    ethopt->eth_type = ETH_TYPE_ARP;
                else
                    error("invalid Ethernet type specification");
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == ARP)
    {
        arpopt = (struct arpopt *)malloc(sizeof(struct arpopt));
        if (arpopt == NULL)
            error("malloc(): cannot allocate memory for arpopt");
        memset(arpopt, 0, sizeof(struct arpopt));
        while ((c = getopt(argc, argv, "o:s:p:t:q:")) != -1)
        {
            switch (c)
            {
            case 'o': /* opcode */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > USHRT_MAX)
                    error("ARP opcode is out of range");
                arpopt->ar_op = (uint16_t)v;
                arpopt->ar_op_flag = 1;
                break;
            case 's': /* sender MAC */
                set_eth_addr_options(optarg, &arpopt->sha);
                break;
            case 'p': /* sender IP */
                str = strdup(optarg);
                if (str == NULL)
                    error("strdup(): cannot allocate memory for str");
                if ((cp = (char *)strtok(str, ",")) == NULL)
                    error("invalid sender IP address");
                if (inet_pton(AF_INET, cp, &(arpopt->ar_old_spa)) != 1)
                    error("invalid sender IP address");
                if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all sender IP address */
                    arpopt->ar_spa_flag = 1;
                else
                { /* overwrite matching IP address only */
                    arpopt->ar_spa_flag = 2;
                    if (inet_pton(AF_INET, cp, &(arpopt->ar_new_spa)) != 1)
                        error("invalid sender IP address");
                }
                free(str);
                str = NULL;
                break;
            case 't': /* target MAC */
                set_eth_addr_options(optarg, &arpopt->tha);
                break;
            case 'q': /* target IP */
                str = strdup(optarg);
                if (str == NULL)
                    error("strdup(): cannot allocate memory for str");
                if ((cp = (char *)strtok(str, ",")) == NULL)
                    error("invalid target IP address");
                if (inet_pton(AF_INET, cp, &(arpopt->ar_old_tpa)) != 1)
                    error("invalid target IP address");
                if ((cp = (char *)strtok(NULL, ",")) == NULL) /* overwrite all target IP address */
                    arpopt->ar_tpa_flag = 1;
                else
                { /* overwrite matching IP address only */
                    arpopt->ar_tpa_flag = 2;
                    if (inet_pton(AF_INET, cp, &(arpopt->ar_new_tpa)) != 1)
                        error("invalid target IP address");
                }
                free(str);
                str = NULL;
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == IP)
    {
        ipopt = (struct ipopt *)malloc(sizeof(struct ipopt));
        if (ipopt == NULL)
            error("malloc(): cannot allocate memory for ipopt");
        memset(ipopt, 0, sizeof(struct ipopt));
        while ((c = getopt(argc, argv, "c:e:i:f:o:t:p:s:d:")) != -1)
        {
            switch (c)
            {
            case 'c': /* 6-bit DS field ('c' for codepoints; 'd' taken by destination IP) */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > DS_FIELD_MAX)
                    error("DS field is out of range");
                ipopt->ip_ds_field = (uint8_t)v;
                ipopt->ip_ds_field_flag = 1;
                break;
            case 'e': /* 2-bit ECN field */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > ECN_FIELD_MAX)
                    error("ECN field is out of range");
                ipopt->ip_ecn_field = (uint8_t)v;
                ipopt->ip_ecn_field_flag = 1;
                break;
            case 'i': /* identification */
                set_number_options(optarg, &ipopt->ip_old_id, &ipopt->ip_new_id, &ipopt->ip_id_flag,
                                   sizeof(uint16_t));
                break;
            case 'f': /* flags */
                for (c = 0; optarg[c]; c++)
                    optarg[c] = tolower(optarg[c]);
                if (strchr(optarg, 'r') != NULL) /* reserved bit */
                    ipopt->ip_flag_r = 1;
                if (strchr(optarg, 'd') != NULL) /* don't fragment bit */
                    ipopt->ip_flag_d = 1;
                if (strchr(optarg, 'm') != NULL) /* more fragment bit */
                    ipopt->ip_flag_m = 1;
                if (strchr(optarg, '-') != NULL)
                { /* remove flags */
                    ipopt->ip_flag_r = 0;
                    ipopt->ip_flag_d = 0;
                    ipopt->ip_flag_m = 0;
                }
                ipopt->ip_flags_flag = 1;
                break;
            case 'o': /* fragment offset */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > IP_FO_MAX)
                    error("IP fragment offset is out of range");
                ipopt->ip_fo = (uint16_t)v;
                ipopt->ip_fo_flag = 1;
                break;
            case 't': /* time to live */
                set_number_options(optarg, &ipopt->ip_old_ttl, &ipopt->ip_new_ttl,
                                   &ipopt->ip_ttl_flag, sizeof(uint8_t));
                break;
            case 'p': /* protocol */
                set_number_options(optarg, &ipopt->ip_old_p, &ipopt->ip_new_p, &ipopt->ip_p_flag,
                                   sizeof(uint8_t));
                break;
            case 's': /* source IP */
                set_in_addr_options(optarg, &ipopt->ip_src);
                break;
            case 'd': /* destination IP */
                set_in_addr_options(optarg, &ipopt->ip_dst);
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == IP6)
    {
        ip6opt = (struct ip6opt *)malloc(sizeof(struct ip6opt));
        if (ip6opt == NULL)
            error("malloc(): cannot allocate memory for ip6opt");
        memset(ip6opt, 0, sizeof(struct ip6opt));
        while ((c = getopt(argc, argv, "c:e:f:n:h:s:d:")) != -1)
        {
            switch (c)
            {
            case 'c': /* 6-bit DS field ('c' for codepoints; 'd' taken by destination IP) */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > DS_FIELD_MAX)
                    error("DS field is out of range");
                ip6opt->ip6_ds_field = (uint8_t)v;
                ip6opt->ip6_ds_field_flag = 1;
                break;
            case 'e': /* 2-bit ECN field */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > ECN_FIELD_MAX)
                    error("ECN field is out of range");
                ip6opt->ip6_ecn_field = (uint8_t)v;
                ip6opt->ip6_ecn_field_flag = 1;
                break;
            case 'f': /* 20-bit flow label: 0x00000 to 0xfffff (1048575) */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > IP6_FLOW_LABEL_MAX)
                    error("IPv6 flow label is out of range");
                ip6opt->ip6_flow_label = (uint32_t)v;
                ip6opt->ip6_flow_label_flag = 1;
                break;
            case 'n': /* 8-bit next header */
                set_number_options(optarg, &ip6opt->ip6_old_next_header,
                                   &ip6opt->ip6_new_next_header, &ip6opt->ip6_next_header_flag,
                                   sizeof(uint8_t));
                break;
            case 'h': /* 8-bit hop limit */
                set_number_options(optarg, &ip6opt->ip6_old_hop_limit, &ip6opt->ip6_new_hop_limit,
                                   &ip6opt->ip6_hop_limit_flag, sizeof(uint8_t));
                break;
            case 's': /* source IP */
                set_in6_addr_options(optarg, &ip6opt->ip6_src);
                break;
            case 'd': /* destination IP */
                set_in6_addr_options(optarg, &ip6opt->ip6_dst);
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == ICMP)
    {
        icmpopt = (struct icmpopt *)malloc(sizeof(struct icmpopt));
        if (icmpopt == NULL)
            error("malloc(): cannot allocate memory for icmpopt");
        memset(icmpopt, 0, sizeof(struct icmpopt));
        while ((c = getopt(argc, argv, "t:c:")) != -1)
        {
            switch (c)
            {
            case 't': /* type, e.g. 8 for echo request, 0 for echo reply */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > UCHAR_MAX)
                    error("ICMP type is out of range");
                icmpopt->icmp_type = (uint8_t)v;
                icmpopt->icmp_type_flag = 1;
                break;
            case 'c': /* code */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > UCHAR_MAX)
                    error("ICMP code is out of range");
                icmpopt->icmp_code = (uint8_t)v;
                icmpopt->icmp_code_flag = 1;
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == ICMP6)
    {
        icmp6opt = (struct icmp6opt *)malloc(sizeof(struct icmp6opt));
        if (icmp6opt == NULL)
            error("malloc(): cannot allocate memory for icmp6opt");
        memset(icmp6opt, 0, sizeof(struct icmp6opt));
        while ((c = getopt(argc, argv, "t:c:")) != -1)
        {
            switch (c)
            {
            case 't': /* type, e.g. 128 for echo request, 129 for echo reply */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > UCHAR_MAX)
                    error("ICMPv6 type is out of range");
                icmp6opt->icmp6_type = (uint8_t)v;
                icmp6opt->icmp6_type_flag = 1;
                break;
            case 'c': /* code */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > UCHAR_MAX)
                    error("ICMPv6 code is out of range");
                icmp6opt->icmp6_code = (uint8_t)v;
                icmp6opt->icmp6_code_flag = 1;
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == TCP)
    {
        tcpopt = (struct tcpopt *)malloc(sizeof(struct tcpopt));
        if (tcpopt == NULL)
            error("malloc(): cannot allocate memory for tcpopt");
        memset(tcpopt, 0, sizeof(struct tcpopt));
        while ((c = getopt(argc, argv, "s:d:q:a:f:w:u:")) != -1)
        {
            switch (c)
            {
            case 's': /* source port */
                set_number_options(optarg, &tcpopt->th_old_sport, &tcpopt->th_new_sport,
                                   &tcpopt->th_sport_flag, sizeof(uint16_t));
                break;
            case 'd': /* destination port */
                set_number_options(optarg, &tcpopt->th_old_dport, &tcpopt->th_new_dport,
                                   &tcpopt->th_dport_flag, sizeof(uint16_t));
                break;
            case 'q': /* sequence number */
                set_number_options(optarg, &tcpopt->th_old_seq, &tcpopt->th_new_seq,
                                   &tcpopt->th_seq_flag, sizeof(uint32_t));
                break;
            case 'a': /* acknowledgment number */
                set_number_options(optarg, &tcpopt->th_old_ack, &tcpopt->th_new_ack,
                                   &tcpopt->th_ack_flag, sizeof(uint32_t));
                break;
            case 'f': /* flags */
                for (c = 0; optarg[c]; c++)
                    optarg[c] = tolower(optarg[c]);
                if (strchr(optarg, 'c') != NULL) /* CWR */
                    tcpopt->th_flag_c = 1;
                if (strchr(optarg, 'e') != NULL) /* ECE */
                    tcpopt->th_flag_e = 1;
                if (strchr(optarg, 'u') != NULL) /* URG */
                    tcpopt->th_flag_u = 1;
                if (strchr(optarg, 'a') != NULL) /* ACK */
                    tcpopt->th_flag_a = 1;
                if (strchr(optarg, 'p') != NULL) /* PSH */
                    tcpopt->th_flag_p = 1;
                if (strchr(optarg, 'r') != NULL) /* RST */
                    tcpopt->th_flag_r = 1;
                if (strchr(optarg, 's') != NULL) /* SYN */
                    tcpopt->th_flag_s = 1;
                if (strchr(optarg, 'f') != NULL) /* FIN */
                    tcpopt->th_flag_f = 1;
                if (strchr(optarg, '-') != NULL)
                { /* remove flags */
                    tcpopt->th_flag_c = 0;
                    tcpopt->th_flag_e = 0;
                    tcpopt->th_flag_u = 0;
                    tcpopt->th_flag_a = 0;
                    tcpopt->th_flag_p = 0;
                    tcpopt->th_flag_r = 0;
                    tcpopt->th_flag_s = 0;
                    tcpopt->th_flag_f = 0;
                }
                tcpopt->th_flags_flag = 1;
                break;
            case 'w': /* window size */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > USHRT_MAX)
                    error("TCP window size is out of range");
                tcpopt->th_win = (uint16_t)v;
                tcpopt->th_win_flag = 1;
                break;
            case 'u': /* urgent pointer */
                v = strtol(optarg, NULL, 0);
                if (v < 0 || v > USHRT_MAX)
                    error("TCP urgent pointer is out of range");
                tcpopt->th_urp = (uint16_t)v;
                tcpopt->th_urp_flag = 1;
                break;
            default:
                usage();
            }
        }
    }
    else if (header_opt == UDP)
    {
        udpopt = (struct udpopt *)malloc(sizeof(struct udpopt));
        if (udpopt == NULL)
            error("malloc(): cannot allocate memory for udpopt");
        memset(udpopt, 0, sizeof(struct udpopt));
        while ((c = getopt(argc, argv, "s:d:")) != -1)
        {
            switch (c)
            {
            case 's': /* source port */
                set_number_options(optarg, &udpopt->uh_old_sport, &udpopt->uh_new_sport,
                                   &udpopt->uh_sport_flag, sizeof(uint16_t));
                break;
            case 'd': /* destination port */
                set_number_options(optarg, &udpopt->uh_old_dport, &udpopt->uh_new_dport,
                                   &udpopt->uh_dport_flag, sizeof(uint16_t));
                break;
            default:
                usage();
            }
        }
    }
    /* NOTREACHED */
}

void parse_trace(char *infile, char *outfile)
{
    FILE *fp;         /* file pointer to input file */
    FILE *fp_outfile; /* file pointer to output file */
    struct pcap_file_header preamble;
    struct pcap_sf_pkthdr *header;
    uint8_t *pkt_data;    /* original packet data starting from link-layer hdr */
    int repeat_index = 0; /* to track number of times we have read input file */
    int pkt_index; /* to check if we are within start_opt and end_opt for range specification */

    load_input_file(infile, &fp);

    notice("output file: %s", outfile);
    if ((fp_outfile = fopen(outfile, "wb")) == NULL)
        error("fopen(): error creating %s", outfile);

    /* preamble occupies the first 24 bytes of a trace file */
    if (fread(&preamble, sizeof(preamble), 1, fp) == 0)
        error("fread(): error reading %s", infile);
    if (preamble.magic != PCAP_MAGIC && preamble.magic != NSEC_PCAP_MAGIC)
        error("%s is not a valid pcap based trace file", infile);

    /* we have timestamps in nanosecond resolution */
    if (preamble.magic == NSEC_PCAP_MAGIC)
        nsec = true;

    /* override pcap preamble link type with user specified link type */
    if (linktype_opt >= 0)
        preamble.linktype = linktype_opt;

    /* write preamble to output file */
    if (fwrite(&preamble, sizeof(preamble), 1, fp_outfile) != 1)
        error("fwrite(): error writing %s", outfile);

    /* pcap hdr */
    header = (struct pcap_sf_pkthdr *)calloc(1, PCAP_HDR_LEN);
    if (header == NULL)
        error("calloc(): cannot allocate memory for header");

    /* check -N to duplicate packets */
    while (repeat_index <= repeat_opt)
    {
        /*
         * loop through the remaining data by reading the pcap hdr first.
         * pcap hdr (16 bytes) = secs. + usecs./nsecs. + caplen + len
         */
        pkt_index = 1;
        while (fread(header, PCAP_HDR_LEN, 1, fp))
        {
            /* original packet data starting from link-layer hdr */
            pkt_data = (uint8_t *)malloc(sizeof(uint8_t) * header->caplen);
            if (pkt_data == NULL)
                error("malloc(): cannot allocate memory for pkt_data");

            /* copy captured packet data starting from link-layer hdr into pkt_data */
            if (fread(pkt_data, header->caplen, 1, fp) == 0)
                error("fread(): error reading %s", infile);

            /* check -R to select range of packets */
            if ((pkt_index >= start_opt && pkt_index <= end_opt) ||
                (start_opt == 0 && end_opt == 0))
            {
                /* check -S to select packets within a timeframe */
                if ((header->ts.tv_sec >= start_sec_opt && header->ts.tv_sec <= end_sec_opt) ||
                    (start_sec_opt == 0 && end_sec_opt == 0))
                {
                    /* check -D to truncate packet */
                    if (start_oset_opt != 0 && end_oset_opt != 0 &&
                        start_oset_opt <= header->caplen)
                        truncate_packet(pkt_data, header, outfile, &fp_outfile);
                    else
                        modify_packet(pkt_data, header, outfile, &fp_outfile);
                    ++pkts; /* packets written */
                }
            }

            free(pkt_data);
            pkt_data = NULL;
            ++pkt_index;
        }
        /* reset to start of input file and skip preamble */
        if (fseek(fp, sizeof(preamble), SEEK_SET) != 0)
            error("fseek(): error reading %s", infile);
        ++repeat_index;
    }

    /* get bytes written */
    if (fseek(fp_outfile, 0, SEEK_END) != 0)
        error("fseek(): error writing %s", outfile);
    bytes = ftell(fp_outfile);
    if (bytes == -1)
        error("ftell(): error writing %s", outfile);

    free(header);
    header = NULL;
    (void)fclose(fp);
    (void)fclose(fp_outfile);
}

void truncate_packet(const uint8_t *pkt_data, struct pcap_sf_pkthdr *header, char *outfile,
                     FILE **fp_outfile)
{
    int i;
    int len;   /* original header->caplen */
    int end_o; /* aligned end_oset_opt */

    /* align end_oset_opt so that it does not go beyond header->caplen */
    if (end_oset_opt > header->caplen)
        end_o = header->caplen;
    else
        end_o = end_oset_opt;

    len = header->caplen; /* original capture length (before byte deletion) */
    header->caplen = header->len = len - ((end_o - start_oset_opt) + 1);

    /* write pcap header */
    if (fwrite(header, PCAP_HDR_LEN, 1, *fp_outfile) != 1)
        error("fwrite(): error writing %s", outfile);

    for (i = 0; i < start_oset_opt - 1; i++)
    {
        if (fputc(pkt_data[i], *fp_outfile) == EOF)
            error("fputc(): error writing %s", outfile);
    }

    for (i = end_o; i < len; i++)
    {
        if (fputc(pkt_data[i], *fp_outfile) == EOF)
            error("fputc(): error writing %s", outfile);
    }
}

void modify_packet(const uint8_t *pkt_data, struct pcap_sf_pkthdr *header, char *outfile,
                   FILE **fp_outfile)
{
    uint8_t *new_pkt_data; /* modified pkt_data inclusive of pcap hdr is written here */
    int ret;
    int i;

    /* modified pkt_data inclusive of pcap hdr */
    new_pkt_data =
        (uint8_t *)malloc(sizeof(uint8_t) * (PCAP_HDR_LEN + ETH_MAX_LEN)); /* 16 + 1514 bytes */
    if (new_pkt_data == NULL)
        error("malloc(): cannot allocate memory for new_pkt_data");
    memset(new_pkt_data, 0, PCAP_HDR_LEN + ETH_MAX_LEN);

    /*
     * encapsulated editing function starting from link-layer hdr.
     * parse_eth() returns bytes written in new_pkt_data starting from link-layer hdr
     */
    ret = parse_eth(pkt_data, new_pkt_data, header) + PCAP_HDR_LEN;

    /* we are editing pcap hdr to apply custom inter-packet gap */
    if (gap_start_opt > 0)
        update_pcap_hdr(header);

    /* copy pcap hdr into new_pkt_data */
    memcpy(new_pkt_data, header, PCAP_HDR_LEN);

    /* no changes */
    if (ret == PCAP_HDR_LEN)
    { /* parse_eth() returns 0 */
        /* write pcap hdr */
        if (fwrite(header, PCAP_HDR_LEN, 1, *fp_outfile) != 1)
            error("fwrite(): error writing %s", outfile);

        if (fwrite(pkt_data, header->caplen, 1, *fp_outfile) != 1)
            error("fwrite(): error writing %s", outfile);
    }
    /* overwrite the entire pkt_data with new_pkt_data */
    else if (ret == header->caplen + PCAP_HDR_LEN)
    {
        if (fwrite(new_pkt_data, ret, 1, *fp_outfile) != 1)
            error("fwrite(): error writing %s", outfile);
    }
    else
    {
        if (fwrite(new_pkt_data, ret, 1, *fp_outfile) != 1)
            error("fwrite(): error writing %s", outfile);

        /* write remaining bytes from pkt_data */
        for (i = ret - PCAP_HDR_LEN; i < header->caplen; i++)
        {
            if (fputc(pkt_data[i], *fp_outfile) == EOF)
                error("fputc(): error writing %s", outfile);
        }
    }

    free(new_pkt_data);
    new_pkt_data = NULL;
}

void load_input_file(char *infile, FILE **fp)
{
    /* attempt to load from built-in template first, i.e. without actual input file */
    if (strcasecmp(infile, "eth") == 0)
    {
        notice("input file: %s (Ethernet header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_ETH, TEMPLATE_PCAP_ETH_LEN, "r");
    }
    else if (strcasecmp(infile, "arp") == 0)
    {
        notice("input file: %s (ARP header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_ARP, TEMPLATE_PCAP_ARP_LEN, "r");
    }
    else if (strcasecmp(infile, "ip") == 0)
    {
        notice("input file: %s (IPv4 header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_IP, TEMPLATE_PCAP_IP_LEN, "r");
    }
    else if (strcasecmp(infile, "ip6") == 0)
    {
        notice("input file: %s (IPv6 header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_IP6, TEMPLATE_PCAP_IP6_LEN, "r");
    }
    else if (strcasecmp(infile, "icmp") == 0)
    {
        notice("input file: %s (ICMPv4 header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_ICMP, TEMPLATE_PCAP_ICMP_LEN, "r");
    }
    else if (strcasecmp(infile, "icmp6") == 0)
    {
        notice("input file: %s (ICMPv6 header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_ICMP6, TEMPLATE_PCAP_ICMP6_LEN, "r");
    }
    else if (strcasecmp(infile, "tcp") == 0)
    {
        notice("input file: %s (IPv4 TCP header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_TCP, TEMPLATE_PCAP_TCP_LEN, "r");
    }
    else if (strcasecmp(infile, "ip6tcp") == 0)
    {
        notice("input file: %s (IPv6 TCP header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_IP6_TCP, TEMPLATE_PCAP_IP6_TCP_LEN, "r");
    }
    else if (strcasecmp(infile, "udp") == 0)
    {
        notice("input file: %s (IPv4 UDP header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_UDP, TEMPLATE_PCAP_UDP_LEN, "r");
    }
    else if (strcasecmp(infile, "ip6udp") == 0)
    {
        notice("input file: %s (IPv6 UDP header template)", infile);
        *fp = fmemopen((void *)TEMPLATE_PCAP_IP6_UDP, TEMPLATE_PCAP_IP6_UDP_LEN, "r");
    }
    else
    {
        /* load actual input file */
        notice("input file: %s", infile);
        if ((*fp = fopen(infile, "rb")) == NULL)
            error("fopen(): error reading %s", infile);
    }
}

void update_pcap_hdr(struct pcap_sf_pkthdr *header)
{
    uint64_t us;

    if (gap_start_opt == gap_end_opt)
        us = gap_start_opt;
    else
        us = gap_start_opt + get_random_number(gap_end_opt - gap_start_opt);

    if (nsec)
        pcap_timeval_nsadd(&gap_last_ts, us * 1000);
    else
        pcap_timeval_usadd(&gap_last_ts, us);

    header->ts = gap_last_ts;
}

uint16_t parse_eth(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header)
{
    /*
     * Ethernet header (14 bytes)
     * 1. destination MAC (6 bytes)
     * 2. source MAC (6 bytes)
     * 3. type (2 bytes)
     */
    struct ethhdr *eth_hdr;
    uint16_t eth_type;
    int i;

    /* do nothing if Ethernet hdr is truncated */
    if (header->caplen < ETH_HDR_LEN)
        return (0);

    eth_hdr = (struct ethhdr *)malloc(ETH_HDR_LEN);
    if (eth_hdr == NULL)
        error("malloc(): cannot allocate memory for eth_hdr");

    /* copy Ethernet hdr from pkt_data into eth_hdr */
    memcpy(eth_hdr, pkt_data, ETH_HDR_LEN);

    /* we are editing Ethernet hdr */
    if (header_opt == ETH)
        update_eth_hdr(eth_hdr);

    eth_type = ntohs(eth_hdr->eth_type);

    /*
     * go pass pcap hdr in new_pkt_data
     * then copy eth_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, eth_hdr, ETH_HDR_LEN);
    free(eth_hdr);
    eth_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN)
        (void)*new_pkt_data--;

    /* copy up to layer 2 only, discard remaining data */
    if (layer_opt == 2)
    {
        /* we are editing Ethernet hdr and we have payload */
        if (header_opt == ETH && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN) > ETH_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETH_HDR_LEN) - ETH_MAX_LEN;
            /*
             * go pass pcap hdr and Ethernet hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
                (void)*new_pkt_data--;

            header->caplen = header->len = ETH_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETH_HDR_LEN;

        return (header->caplen);
    }

    /* parse ARP datagram */
    if (eth_type == ETH_TYPE_ARP)
        return (parse_arp(pkt_data, new_pkt_data, header));
    /* parse IP datagram */
    else if (eth_type == ETH_TYPE_IP)
        return (parse_ip(pkt_data, new_pkt_data, header, NULL, 0));
    /* parse IPv6 datagram */
    else if (eth_type == ETH_TYPE_IPV6)
        return (parse_ip6(pkt_data, new_pkt_data, header));
    /* no further editing support for other datagram */
    else
        return (ETH_HDR_LEN);
}

void update_eth_hdr(struct ethhdr *eth_hdr)
{
    /* overwrite destination MAC */
    if (ethopt->dhost.flag == FIELD_SET)
        memcpy(eth_hdr->eth_dhost, ethopt->dhost.old, ETH_ADDR_LEN);
    else if (ethopt->dhost.flag == FIELD_REPLACE &&
             memcmp(eth_hdr->eth_dhost, ethopt->dhost.old, ETH_ADDR_LEN) == 0)
        memcpy(eth_hdr->eth_dhost, ethopt->dhost.new, ETH_ADDR_LEN);
    else if (ethopt->dhost.flag == FIELD_SET_RAND ||
             (ethopt->dhost.flag == FIELD_REPLACE_RAND &&
              memcmp(eth_hdr->eth_dhost, ethopt->dhost.old, ETH_ADDR_LEN) == 0))
        set_random_eth_addr(eth_hdr->eth_dhost);

    /* overwrite source MAC */
    if (ethopt->shost.flag == FIELD_SET)
        memcpy(eth_hdr->eth_shost, ethopt->shost.old, ETH_ADDR_LEN);
    else if (ethopt->shost.flag == FIELD_REPLACE &&
             memcmp(eth_hdr->eth_shost, ethopt->shost.old, ETH_ADDR_LEN) == 0)
        memcpy(eth_hdr->eth_shost, ethopt->shost.new, ETH_ADDR_LEN);
    else if (ethopt->shost.flag == FIELD_SET_RAND ||
             (ethopt->shost.flag == FIELD_REPLACE_RAND &&
              memcmp(eth_hdr->eth_shost, ethopt->shost.old, ETH_ADDR_LEN) == 0))
        set_random_eth_addr(eth_hdr->eth_shost);

    /* overwrite Ethernet type */
    if (ethopt->eth_type != 0)
        eth_hdr->eth_type = htons(ethopt->eth_type);
}

uint16_t parse_arp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header)
{
    /*
     * Ethernet ARP header (28 bytes)
     *  1. hardware type (2 bytes)
     *  2. protocol type (2 bytes)
     *  3. hardware address length (1 byte)
     *  4. protocol address length (1 byte)
     *  5. opcode (2 bytes)
     *  6. sender hardware address (6 bytes)
     *  7. sender protocol address (4 bytes)
     *  8. target hardware address (6 bytes)
     *  9. target protocol address (4 bytes)
     */
    struct arphdr *arp_hdr;
    int i;

    /* do nothing if ARP hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + ARP_HDR_LEN)
        return (ETH_HDR_LEN);

    /* go pass Ethernet hdr in pkt_data */
    i = 0;
    while (i++ < ETH_HDR_LEN)
        (void)*pkt_data++;

    arp_hdr = (struct arphdr *)malloc(ARP_HDR_LEN);
    if (arp_hdr == NULL)
        error("malloc(): cannot allocate memory for arp_hdr");

    /* copy ARP hdr from pkt_data into arp_hdr */
    memcpy(arp_hdr, pkt_data, ARP_HDR_LEN);

    /* reset pointer to the beginning of pkt_data */
    i = 0;
    while (i++ < ETH_HDR_LEN)
        (void)*pkt_data--;

    /* do nothing if this is an unsupported ARP hdr */
    if (arp_hdr->ar_hln != ETH_ADDR_LEN || arp_hdr->ar_pln != IP_ADDR_LEN)
    {
        free(arp_hdr);
        arp_hdr = NULL;
        return (ETH_HDR_LEN);
    }

    /* we are editing ARP hdr */
    if (header_opt == ARP)
        update_arp_hdr(arp_hdr);

    /*
     * go pass pcap hdr and Ethernet hdr in new_pkt_data
     * then copy arp_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, arp_hdr, ARP_HDR_LEN);
    free(arp_hdr);
    arp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
        (void)*new_pkt_data--;

    /* copy up to layer 3 only, discard remaining data */
    if (layer_opt == 3)
    {
        /* we are editing ARP hdr and we have payload */
        if (header_opt == ARP && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN + ARP_HDR_LEN) > ETH_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETH_HDR_LEN + ARP_HDR_LEN) - ETH_MAX_LEN;
            /*
             * go pass pcap hdr, Ethernet hdr and ARP hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ARP_HDR_LEN)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ARP_HDR_LEN)
                (void)*new_pkt_data--;

            header->caplen = header->len = ETH_HDR_LEN + ARP_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETH_HDR_LEN + ARP_HDR_LEN;

        return (header->caplen);
    }

    /* no further editing support after ARP hdr */
    return (ETH_HDR_LEN + ARP_HDR_LEN);
}

void update_arp_hdr(struct arphdr *arp_hdr)
{
    /* overwrite opcode */
    if (arpopt->ar_op_flag)
        arp_hdr->ar_op = htons(arpopt->ar_op);

    /* overwrite sender MAC */
    if (arpopt->sha.flag == FIELD_SET)
        memcpy(arp_hdr->ar_sha, arpopt->sha.old, ETH_ADDR_LEN);
    else if (arpopt->sha.flag == FIELD_REPLACE &&
             memcmp(arp_hdr->ar_sha, arpopt->sha.old, ETH_ADDR_LEN) == 0)
        memcpy(arp_hdr->ar_sha, arpopt->sha.new, ETH_ADDR_LEN);
    else if (arpopt->sha.flag == FIELD_SET_RAND ||
             (arpopt->sha.flag == FIELD_REPLACE_RAND &&
              memcmp(arp_hdr->ar_sha, arpopt->sha.old, ETH_ADDR_LEN) == 0))
        set_random_eth_addr(arp_hdr->ar_sha);

    /* overwrite sender IP */
    if (arpopt->ar_spa_flag == 1) /* overwrite all sender IP */
        memcpy(arp_hdr->ar_spa, arpopt->ar_old_spa, IP_ADDR_LEN);
    else if (arpopt->ar_spa_flag == 2 && /* overwrite matching IP only */
             memcmp(arp_hdr->ar_spa, arpopt->ar_old_spa, IP_ADDR_LEN) == 0)
        memcpy(arp_hdr->ar_spa, arpopt->ar_new_spa, IP_ADDR_LEN);

    /* overwrite target MAC */
    if (arpopt->tha.flag == FIELD_SET)
        memcpy(arp_hdr->ar_tha, arpopt->tha.old, ETH_ADDR_LEN);
    else if (arpopt->tha.flag == FIELD_REPLACE &&
             memcmp(arp_hdr->ar_tha, arpopt->tha.old, ETH_ADDR_LEN) == 0)
        memcpy(arp_hdr->ar_tha, arpopt->tha.new, ETH_ADDR_LEN);
    else if (arpopt->tha.flag == FIELD_SET_RAND ||
             (arpopt->tha.flag == FIELD_REPLACE_RAND &&
              memcmp(arp_hdr->ar_tha, arpopt->tha.old, ETH_ADDR_LEN) == 0))
        set_random_eth_addr(arp_hdr->ar_tha);

    /* overwrite target IP */
    if (arpopt->ar_tpa_flag == 1) /* overwrite all target IP */
        memcpy(arp_hdr->ar_tpa, arpopt->ar_old_tpa, IP_ADDR_LEN);
    else if (arpopt->ar_tpa_flag == 2 && /* overwrite matching IP only */
             memcmp(arp_hdr->ar_tpa, arpopt->ar_old_tpa, IP_ADDR_LEN) == 0)
        memcpy(arp_hdr->ar_tpa, arpopt->ar_new_tpa, IP_ADDR_LEN);
}

uint16_t parse_ip(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                  struct ip *ip_hdr, int flag)
{
    /*
     * IP header (20 bytes + optional X bytes for options)
     *  1. version (4 bits)
     *  2. header length (4 bits)
     *  3. service type (1 byte)
     *  4. total length (2 bytes)
     *  5. id (2 bytes)
     *  6. flag (3 bits)
     *  7. fragment offset (13 bits)
     *  8. ttl (1 byte)
     *  9. protocol (1 byte)
     * 10. header checksum (2 bytes)
     * 11. source IP (4 bytes)
     * 12. destination IP (4 bytes)
     * 13. options (X bytes)
     */
    uint16_t ip_hlb;  /* hdr length in bytes */
    uint8_t r = '\0'; /* flags */
    uint8_t d = '\0';
    uint8_t m = '\0';
    uint8_t ip_p = '\0';  /* protocol */
    uint8_t *ip_o = NULL; /* options (X bytes) */
    int i, j;

    /*
     * flag is 0; entry from Ethernet hdr to edit IP hdr.
     * flag is 1; entry from ICMP, TCP or UDP hdr to update IP total length and recalculate
     *            checksum for IP hdr.
     */
    if (flag == 0 && ip_hdr == NULL)
    {
        /* do nothing if IP hdr is truncated */
        if (header->caplen < ETH_HDR_LEN + IP_HDR_LEN)
            return (ETH_HDR_LEN);

        /* go pass Ethernet hdr in pkt_data */
        i = 0;
        while (i++ < ETH_HDR_LEN)
            (void)*pkt_data++;

        ip_hdr = (struct ip *)malloc(IP_HDR_LEN);
        if (ip_hdr == NULL)
            error("malloc(): cannot allocate memory for ip_hdr");

        /* copy IP hdr from pkt_data into ip_hdr */
        memcpy(ip_hdr, pkt_data, IP_HDR_LEN);
    }

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* have IP options */
    if (ip_hlb > IP_HDR_LEN)
    {
        /* do nothing if IP hdr with options is truncated */
        if (header->caplen < ETH_HDR_LEN + ip_hlb)
        {
            /* reset pointer to the beginning of pkt_data */
            i = 0;
            while (i++ < ETH_HDR_LEN)
                (void)*pkt_data--;

            free(ip_hdr);
            ip_hdr = NULL;
            return (ETH_HDR_LEN);
        }

        ip_o = (uint8_t *)malloc(sizeof(uint8_t) * (ip_hlb - IP_HDR_LEN));
        if (ip_o == NULL)
            error("malloc(): cannot allocate memory for ip_o");

        /* copy IP options into ip_o */
        for (i = 0, j = IP_HDR_LEN; i < (ip_hlb - IP_HDR_LEN); i++, j++)
            ip_o[i] = pkt_data[j];
    }

    if (flag == 0)
    {
        /* reset pointer to the beginning of pkt_data */
        i = 0;
        while (i++ < ETH_HDR_LEN)
            (void)*pkt_data--;

        /* we are editing IP hdr */
        if (header_opt == IP)
        {
            /* original flags */
            r = (ntohs(ip_hdr->ip_off) & IP_RF) > 0 ? 1 : 0;
            d = (ntohs(ip_hdr->ip_off) & IP_DF) > 0 ? 1 : 0;
            m = (ntohs(ip_hdr->ip_off) & IP_MF) > 0 ? 1 : 0;

            update_ip_hdr(ip_hdr, &r, &d, &m);
        }

        /*
         * if more fragment flag is set, we should not parse the protocol hdr
         * (ICMP, TCP, or UDP) just yet since this is a fragmented packet
         */
        m = (ntohs(ip_hdr->ip_off) & IP_MF) > 0 ? 1 : 0;
        ip_p = ip_hdr->ip_p;

        /* we are going to copy up to layer 3 only, change total length */
        if (layer_opt == 3)
        {
            /* we are editing IP hdr and we have payload, include its length in total length */
            if (header_opt == IP && payload_len_opt > 0)
            {
                /* truncate payload if it is too large */
                if ((payload_len_opt + ETH_HDR_LEN + ip_hlb) > ETH_MAX_LEN)
                    payload_len_opt -= (payload_len_opt + ETH_HDR_LEN + ip_hlb) - ETH_MAX_LEN;
                ip_hdr->ip_len = htons(ip_hlb + payload_len_opt);
            }
            else
                ip_hdr->ip_len = htons(ip_hlb);
        }
    }

    /* recalculate checksum (cover IP hdr only) */
    if (csum_opt)
        update_ip_cksum(ip_hdr, ip_o, &ip_hlb);

    /*
     * go pass pcap hdr and Ethernet hdr in new_pkt_data
     * then copy ip_hdr and ip_o (if exist) into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, ip_hdr, IP_HDR_LEN);

    /* have IP options */
    if (ip_hlb > IP_HDR_LEN)
    {
        i = 0;
        while (i++ < IP_HDR_LEN)
            (void)*new_pkt_data++;

        memcpy(new_pkt_data, ip_o, ip_hlb - IP_HDR_LEN);
        free(ip_o);
        ip_o = NULL;

        i = 0;
        while (i++ < IP_HDR_LEN)
            (void)*new_pkt_data--;
    }

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
        (void)*new_pkt_data--;

    if (flag == 0)
    {
        /* copy up to layer 3 only, discard remaining data */
        if (layer_opt == 3)
        {
            /* we are editing IP hdr and we have payload */
            if (header_opt == IP && payload_len_opt > 0)
            {
                /*
                 * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
                 * then copy payload_opt into new_pkt_data
                 * and reset pointer to the beginning of new_pkt_data
                 */
                i = 0;
                while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
                    (void)*new_pkt_data++;

                memcpy(new_pkt_data, payload_opt, payload_len_opt);

                i = 0;
                while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
                    (void)*new_pkt_data--;

                header->caplen = header->len = ETH_HDR_LEN + ip_hlb + payload_len_opt;

                /*
                 * if payload is specified and it applies to ICMP, TCP, or UDP hdr + data,
                 * and checksum correction on this payload is needed,
                 * and more fragment flag is not set -> not a fragmented packet
                 */
                if (csum_opt && !m)
                {
                    /* parse ICMP datagram */
                    if (ip_p == IPPROTO_ICMP)
                        return (parse_icmp(pkt_data, new_pkt_data, header, ip_hdr));
                    /* parse TCP datagram */
                    else if (ip_p == IPPROTO_TCP)
                        return (parse_tcp(pkt_data, new_pkt_data, header, ip_hdr));
                    /* parse UDP datagram */
                    else if (ip_p == IPPROTO_UDP)
                        return (parse_udp(pkt_data, new_pkt_data, header, ip_hdr));
                }
            }
            else
                header->caplen = header->len = ETH_HDR_LEN + ip_hlb;

            free(ip_hdr);
            ip_hdr = NULL;
            return (header->caplen);
        }

        /* !m means more fragment flag is not set -> not a fragmented packet */
        if (!m)
        {
            /* parse ICMP datagram */
            if (ip_p == IPPROTO_ICMP)
                return (parse_icmp(pkt_data, new_pkt_data, header, ip_hdr));
            /* parse TCP datagram */
            else if (ip_p == IPPROTO_TCP)
                return (parse_tcp(pkt_data, new_pkt_data, header, ip_hdr));
            /* parse UDP datagram */
            else if (ip_p == IPPROTO_UDP)
                return (parse_udp(pkt_data, new_pkt_data, header, ip_hdr));
        }

        /* no further editing support for other datagram or fragmented packet */
        free(ip_hdr);
        return (ETH_HDR_LEN + ip_hlb);
    }
    return (0); /* flag is 1 */
}

void update_ip_cksum(struct ip *ip_hdr, uint8_t *ip_o, uint16_t *ip_hlb)
{
    uint8_t *ip_hdr_o; /* IP hdr with options (for hdr checksum calculation) */
    int i;

    ip_hdr->ip_sum = 0x0000; /* clear checksum field */

    /* have IP options */
    if (*ip_hlb > IP_HDR_LEN)
    {
        ip_hdr_o = (uint8_t *)malloc(sizeof(uint8_t) * (*ip_hlb));
        if (ip_hdr_o == NULL)
            error("malloc(): cannot allocate memory for ip_hdr_o");

        /*
         * copy ip_hdr into ip_hdr_o, go pass IP hdr in ip_hdr_o
         * then copy ip_o into ip_hdr_o
         * and reset pointer to the beginning of ip_hdr_o
         * and finally calculate checksum of ip_hdr_o
         */
        memcpy(ip_hdr_o, ip_hdr, IP_HDR_LEN);

        i = 0;
        while (i++ < IP_HDR_LEN)
            (void)*ip_hdr_o++;

        memcpy(ip_hdr_o, ip_o, *ip_hlb - IP_HDR_LEN);

        i = 0;
        while (i++ < IP_HDR_LEN)
            (void)*ip_hdr_o--;

        ip_hdr->ip_sum = cksum(ip_hdr_o, *ip_hlb);
        free(ip_hdr_o);
        ip_hdr_o = NULL;
    }
    else
        ip_hdr->ip_sum = cksum((uint8_t *)ip_hdr, *ip_hlb);
}

void update_ip_hdr(struct ip *ip_hdr, uint8_t *r, uint8_t *d, uint8_t *m)
{
    uint16_t ip_fo; /* fragment offset (number of 64-bit segments) */

    /* overwrite first 6-bit (DS field) of 8-bit type of service field */
    if (ipopt->ip_ds_field_flag)
        /* left shifted DS field value by 2-bit ECN field */
        ip_hdr->ip_tos |= ipopt->ip_ds_field << 2;

    /* overwrite last 2-bit (ECN field) of 8-bit type of service field */
    if (ipopt->ip_ecn_field_flag)
        ip_hdr->ip_tos |= ipopt->ip_ecn_field;

    /* overwrite identification */
    if (ipopt->ip_id_flag == FIELD_SET)
        ip_hdr->ip_id = htons(ipopt->ip_old_id);
    else if (ipopt->ip_id_flag == FIELD_REPLACE && ip_hdr->ip_id == htons(ipopt->ip_old_id))
        ip_hdr->ip_id = htons(ipopt->ip_new_id);
    else if (ipopt->ip_id_flag == FIELD_SET_RAND ||
             (ipopt->ip_id_flag == FIELD_REPLACE_RAND && ip_hdr->ip_id == htons(ipopt->ip_old_id)))
        ip_hdr->ip_id = htons(get_random_number(UINT16_MAX));

    /* original fragment offset */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /* overwrite fragment offset only */
    if (ipopt->ip_fo_flag && !ipopt->ip_flags_flag)
    {
        ip_hdr->ip_off = htons((ipopt->ip_fo & IP_OFFMASK) | (*r ? IP_RF : 0) | (*d ? IP_DF : 0) |
                               (*m ? IP_MF : 0));
    }
    /* overwrite flags only */
    else if (!ipopt->ip_fo_flag && ipopt->ip_flags_flag)
    {
        ip_hdr->ip_off = htons((ip_fo & IP_OFFMASK) | ((ipopt->ip_flag_r) ? IP_RF : 0) |
                               ((ipopt->ip_flag_d) ? IP_DF : 0) | ((ipopt->ip_flag_m) ? IP_MF : 0));
    }
    /* overwrite fragment offset and flags */
    else if (ipopt->ip_fo_flag && ipopt->ip_flags_flag)
    {
        ip_hdr->ip_off = htons((ipopt->ip_fo & IP_OFFMASK) | ((ipopt->ip_flag_r) ? IP_RF : 0) |
                               ((ipopt->ip_flag_d) ? IP_DF : 0) | ((ipopt->ip_flag_m) ? IP_MF : 0));
    }

    /* overwrite time to live */
    if (ipopt->ip_ttl_flag == FIELD_SET)
        ip_hdr->ip_ttl = ipopt->ip_old_ttl;
    else if (ipopt->ip_ttl_flag == FIELD_REPLACE && ip_hdr->ip_ttl == ipopt->ip_old_ttl)
        ip_hdr->ip_ttl = ipopt->ip_new_ttl;
    else if (ipopt->ip_ttl_flag == FIELD_SET_RAND ||
             (ipopt->ip_ttl_flag == FIELD_REPLACE_RAND && ip_hdr->ip_ttl == ipopt->ip_old_ttl))
        ip_hdr->ip_ttl = get_random_number(UINT8_MAX);

    /* overwrite protocol */
    if (ipopt->ip_p_flag == FIELD_SET)
        ip_hdr->ip_p = ipopt->ip_old_p;
    else if (ipopt->ip_p_flag == FIELD_REPLACE && ip_hdr->ip_p == htons(ipopt->ip_old_p))
        ip_hdr->ip_p = ipopt->ip_new_p;
    else if (ipopt->ip_p_flag == FIELD_SET_RAND ||
             (ipopt->ip_p_flag == FIELD_REPLACE_RAND && ip_hdr->ip_p == ipopt->ip_old_p))
        ip_hdr->ip_p = get_random_number(UINT8_MAX);

    /* overwrite source IP */
    if (ipopt->ip_src.flag == FIELD_SET)
        memcpy(&ip_hdr->ip_src, &ipopt->ip_src.old, sizeof(struct in_addr));
    else if (ipopt->ip_src.flag == FIELD_REPLACE &&
             memcmp(&ip_hdr->ip_src, &ipopt->ip_src.old, sizeof(struct in_addr)) == 0)
        memcpy(&ip_hdr->ip_src, &ipopt->ip_src.new, sizeof(struct in_addr));
    else if (ipopt->ip_src.flag == FIELD_SET_RAND ||
             (ipopt->ip_src.flag == FIELD_REPLACE_RAND &&
              memcmp(&ip_hdr->ip_src, &ipopt->ip_src.old, sizeof(struct in_addr)) == 0))
        set_random_in_addr(&ip_hdr->ip_src, &ipopt->ip_src);

    /* overwrite destination IP */
    if (ipopt->ip_dst.flag == FIELD_SET)
        memcpy(&ip_hdr->ip_dst, &ipopt->ip_dst.old, sizeof(struct in_addr));
    else if (ipopt->ip_dst.flag == FIELD_REPLACE &&
             memcmp(&ip_hdr->ip_dst, &ipopt->ip_dst.old, sizeof(struct in_addr)) == 0)
        memcpy(&ip_hdr->ip_dst, &ipopt->ip_dst.new, sizeof(struct in_addr));
    else if (ipopt->ip_dst.flag == FIELD_SET_RAND ||
             (ipopt->ip_dst.flag == FIELD_REPLACE_RAND &&
              memcmp(&ip_hdr->ip_dst, &ipopt->ip_dst.old, sizeof(struct in_addr)) == 0))
        set_random_in_addr(&ip_hdr->ip_dst, &ipopt->ip_dst);
}

uint16_t parse_ip6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header)
{
    /*
     * IPv6 header (40 bytes + optional X bytes for extension headers)
     * 1. version (4 bits)
     * 2. traffic class (8 bits)
     * 3. flow label (20 bits)
     * 4. payload length (16 bits) - rest of packet after 40 bytes headers
     * 5. next header (8 bits) - same values as IPv4 protocol field
     * 6. hop limit (8 bits)
     * 7. source address (128 bits)
     * 8. destination address (128 bits)
     * 9. extension headers (X bytes)
     */
    struct ip6 *ip6_hdr;
    int i;

    /* do nothing if IPv6 hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + IP6_HDR_LEN)
        return (ETH_HDR_LEN);

    /* go pass Ethernet hdr in pkt_data */
    i = 0;
    while (i++ < ETH_HDR_LEN)
        (void)*pkt_data++;

    ip6_hdr = (struct ip6 *)malloc(sizeof(struct ip6));
    if (ip6_hdr == NULL)
        error("malloc(): cannot allocate memory for ip6_hdr");

    /* copy IPv6 hdr from pkt_data into ip6_hdr */
    memcpy(ip6_hdr, pkt_data, IP6_HDR_LEN);

    /* reset pointer to the beginning of pkt_data */
    i = 0;
    while (i++ < ETH_HDR_LEN)
        (void)*pkt_data--;

    /* do nothing if next hdr is unsupported */
    if (ip6_hdr->ip6_nxt != IPPROTO_TCP && ip6_hdr->ip6_nxt != IPPROTO_UDP &&
        ip6_hdr->ip6_nxt != IPPROTO_ICMPV6)
    {
        free(ip6_hdr);
        ip6_hdr = NULL;
        return (ETH_HDR_LEN);
    }

    /* we are editing IPv6 hdr */
    if (header_opt == IP6)
        update_ip6_hdr(ip6_hdr);

    /* we are going to copy up to layer 3 only, change payload length */
    if (layer_opt == 3)
    {
        /* we are editing IPv6 hdr and we have payload, use its length as payload length */
        if (header_opt == IP6 && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN) > ETH_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN) - ETH_MAX_LEN;
            ip6_hdr->ip6_plen = htons(payload_len_opt);
        }
        else
            ip6_hdr->ip6_plen = 0;
    }

    write_ip6_hdr(new_pkt_data, ip6_hdr);

    /* copy up to layer 3 only, discard remaining data */
    if (layer_opt == 3)
    {
        /* we are editing IPv6 hdr and we have payload */
        if (header_opt == IP6 && payload_len_opt > 0)
        {
            /*
             * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
                (void)*new_pkt_data--;

            header->caplen = header->len = ETH_HDR_LEN + IP6_HDR_LEN + payload_len_opt;

            /*
             * if payload is specified and it applies to ICMPv6, TCP, or UDP hdr + data,
             * and checksum correction on this payload is needed
             */
            if (csum_opt)
            {
                /* parse ICMPv6 datagram */
                if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6)
                    return (parse_icmp6(pkt_data, new_pkt_data, header, ip6_hdr));
                /* parse TCP datagram */
                else if (ip6_hdr->ip6_nxt == IPPROTO_TCP)
                    return (parse_tcp6(pkt_data, new_pkt_data, header, ip6_hdr));
                /* parse UDP datagram */
                else if (ip6_hdr->ip6_nxt == IPPROTO_UDP)
                    return (parse_udp6(pkt_data, new_pkt_data, header, ip6_hdr));
            }
        }
        else
            header->caplen = header->len = ETH_HDR_LEN + IP6_HDR_LEN;

        free(ip6_hdr);
        ip6_hdr = NULL;
        return (header->caplen);
    }

    /* parse ICMPv6 datagram */
    if (ip6_hdr->ip6_nxt == IPPROTO_ICMPV6)
        return (parse_icmp6(pkt_data, new_pkt_data, header, ip6_hdr));
    /* parse TCP datagram */
    else if (ip6_hdr->ip6_nxt == IPPROTO_TCP)
        return (parse_tcp6(pkt_data, new_pkt_data, header, ip6_hdr));
    /* parse UDP datagram */
    else if (ip6_hdr->ip6_nxt == IPPROTO_UDP)
        return (parse_udp6(pkt_data, new_pkt_data, header, ip6_hdr));

    /* no further editing support for other datagram */
    free(ip6_hdr);
    ip6_hdr = NULL;
    return (ETH_HDR_LEN + IP6_HDR_LEN);
}

void update_ip6_hdr(struct ip6 *ip6_hdr)
{
    /* overwrite first 6-bit (DS field) of 8-bit traffic class field */
    if (ip6opt->ip6_ds_field_flag)
        /* left shifted DS field value by 2-bit ECN field + 20-bit flow label */
        ip6_hdr->ip6_flow |= htonl(ip6opt->ip6_ds_field << 22);

    /* overwrite last 2-bit (ECN field) of 8-bit traffic class field */
    if (ip6opt->ip6_ecn_field_flag)
        /* left shifted ECN field value by 20-bit flow label */
        ip6_hdr->ip6_flow |= htonl(ip6opt->ip6_ecn_field << 20);

    /* overwrite flow label */
    if (ip6opt->ip6_flow_label_flag)
    {
        /* keep 4-bit version and 8-bit traffic class but overwrite 20-bit flow label */
        ip6_hdr->ip6_flow = (ip6_hdr->ip6_flow & ~IP6_FLOWLABEL_MASK) |
                            (htonl(ip6opt->ip6_flow_label) & IP6_FLOWLABEL_MASK);
    }

    /* overwrite next header */
    if (ip6opt->ip6_next_header_flag == FIELD_SET)
        ip6_hdr->ip6_nxt = ip6opt->ip6_old_next_header;
    else if (ip6opt->ip6_next_header_flag == FIELD_REPLACE &&
             ip6_hdr->ip6_nxt == ip6opt->ip6_old_next_header)
        ip6_hdr->ip6_nxt = ip6opt->ip6_new_next_header;
    else if (ip6opt->ip6_next_header_flag == FIELD_SET_RAND ||
             (ip6opt->ip6_next_header_flag == FIELD_REPLACE_RAND &&
              ip6_hdr->ip6_nxt == ip6opt->ip6_old_next_header))
        ip6_hdr->ip6_nxt = get_random_number(UINT8_MAX);

    /* overwrite hop limit */
    if (ip6opt->ip6_hop_limit_flag == FIELD_SET)
        ip6_hdr->ip6_hlim = ip6opt->ip6_old_hop_limit;
    else if (ip6opt->ip6_hop_limit_flag == FIELD_REPLACE &&
             ip6_hdr->ip6_hlim == ip6opt->ip6_old_hop_limit)
        ip6_hdr->ip6_hlim = ip6opt->ip6_new_hop_limit;
    else if (ip6opt->ip6_hop_limit_flag == FIELD_SET_RAND ||
             (ip6opt->ip6_hop_limit_flag == FIELD_REPLACE_RAND &&
              ip6_hdr->ip6_hlim == ip6opt->ip6_old_hop_limit))
        ip6_hdr->ip6_hlim = get_random_number(UINT8_MAX);

    /* overwrite source IP */
    if (ip6opt->ip6_src.flag == FIELD_SET)
        memcpy(&ip6_hdr->ip6_src, &ip6opt->ip6_src.old, sizeof(struct in6_addr));
    else if (ip6opt->ip6_src.flag == FIELD_REPLACE &&
             memcmp(&ip6_hdr->ip6_src, &ip6opt->ip6_src.old, sizeof(struct in6_addr)) == 0)
        memcpy(&ip6_hdr->ip6_src, &ip6opt->ip6_src.new, sizeof(struct in6_addr));
    else if (ip6opt->ip6_src.flag == FIELD_SET_RAND ||
             (ip6opt->ip6_src.flag == FIELD_REPLACE_RAND &&
              memcmp(&ip6_hdr->ip6_src, &ip6opt->ip6_src.old, sizeof(struct in6_addr)) == 0))
        set_random_in6_addr(&ip6_hdr->ip6_src, &ip6opt->ip6_src);

    /* overwrite destination IP */
    if (ip6opt->ip6_dst.flag == FIELD_SET)
        memcpy(&ip6_hdr->ip6_dst, &ip6opt->ip6_dst.old, sizeof(struct in6_addr));
    else if (ip6opt->ip6_dst.flag == FIELD_REPLACE &&
             memcmp(&ip6_hdr->ip6_dst, &ip6opt->ip6_dst.old, sizeof(struct in6_addr)) == 0)
        memcpy(&ip6_hdr->ip6_dst, &ip6opt->ip6_dst.new, sizeof(struct in6_addr));
    else if (ip6opt->ip6_dst.flag == FIELD_SET_RAND ||
             (ip6opt->ip6_dst.flag == FIELD_REPLACE_RAND &&
              memcmp(&ip6_hdr->ip6_dst, &ip6opt->ip6_dst.old, sizeof(struct in6_addr)) == 0))
        set_random_in6_addr(&ip6_hdr->ip6_dst, &ip6opt->ip6_dst);
}

void write_ip6_hdr(uint8_t *new_pkt_data, struct ip6 *ip6_hdr)
{
    int i;

    /*
     * go pass pcap hdr and Ethernet hdr in new_pkt_data
     * then copy ip6_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, ip6_hdr, IP6_HDR_LEN);

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN)
        (void)*new_pkt_data--;
}

uint16_t parse_icmp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                    struct ip *ip_hdr)
{
    /*
     * ICMP header (4 bytes)
     *  1. type (1 byte)
     *  2. code (1 byte)
     *  3. checksum (2 bytes)
     */
    struct icmphdr *icmp_hdr;
    uint16_t ip_hlb; /* IP hdr length in bytes */
    uint16_t ip_fo;  /* IP fragment offset (number of 64-bit segments) */
    int i;

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* do nothing if ICMP hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN)
    {
        free(ip_hdr);
        ip_hdr = NULL;
        return (ETH_HDR_LEN + ip_hlb);
    }

    icmp_hdr = (struct icmphdr *)malloc(ICMP_HDR_LEN);
    if (icmp_hdr == NULL)
        error("malloc(): cannot allocate memory for icmp_hdr");

    /*
     * we have payload which covers ICMP hdr + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
    {
        /*
         * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
         * then copy ICMP hdr from new_pkt_data into icmp_hdr
         * and reset pointer to the beginning of new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
            (void)*new_pkt_data++;

        memcpy(icmp_hdr, new_pkt_data, ICMP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
            (void)*new_pkt_data--;
    }
    else
    {
        /*
         * go pass Ethernet hdr and IP hdr in pkt_data
         * then copy ICMP hdr from pkt_data into icmp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETH_HDR_LEN + ip_hlb))
            (void)*pkt_data++;

        memcpy(icmp_hdr, pkt_data, ICMP_HDR_LEN);

        i = 0;
        while (i++ < (ETH_HDR_LEN + ip_hlb))
            (void)*pkt_data--;

        /* we are editing ICMP hdr */
        if (header_opt == ICMP)
        {
            /* overwrite type */
            if (icmpopt->icmp_type_flag)
                icmp_hdr->icmp_type = icmpopt->icmp_type;

            /* overwrite code */
            if (icmpopt->icmp_code_flag)
                icmp_hdr->icmp_code = icmpopt->icmp_code;
        }

        /* we are going to copy up to layer 4 only */
        if (layer_opt == 4)
        {
            /*
             * we are editing ICMP hdr and we have payload,
             * attach the payload first before checksum calculation
             */
            if (header_opt == ICMP && payload_len_opt > 0)
            {
                /* truncate payload if it is too large */
                if ((payload_len_opt + ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN) > ETH_MAX_LEN)
                    payload_len_opt -=
                        (payload_len_opt + ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN) - ETH_MAX_LEN;

                /*
                 * go pass pcap hdr, Ethernet hdr, IP hdr and ICMP hdr in new_pkt_data
                 * then copy payload_opt into new_pkt_data
                 * and reset pointer to the beginning of new_pkt_data
                 */
                i = 0;
                while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN)
                    (void)*new_pkt_data++;

                memcpy(new_pkt_data, payload_opt, payload_len_opt);

                i = 0;
                while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN)
                    (void)*new_pkt_data--;

                header->caplen = header->len =
                    ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN + payload_len_opt;
            }
            else
                header->caplen = header->len = ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN;

            /* update IP total length */
            ip_hdr->ip_len = htons(header->caplen - ETH_HDR_LEN);

            /* go pass Ethernet hdr in pkt_data */
            i = 0;
            while (i++ < ETH_HDR_LEN)
                (void)*pkt_data++;

            /*
             * reuse parsing function for IP hdr
             * to update IP total length in new_pkt_data
             * and recalculate checksum for IP hdr if required
             */
            (void)parse_ip(pkt_data, new_pkt_data, header, ip_hdr, 1);

            /* reset pointer to the beginning of pkt_data */
            i = 0;
            while (i++ < ETH_HDR_LEN)
                (void)*pkt_data--;
        }
    }

    /* we have no support for checksum calculation for fragmented packet */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /*
     * recalculate checksum for ICMP hdr (cover ICMP hdr + trailing data)
     * if we have enough data
     */
    if (csum_opt && ip_fo == 0 && header->caplen >= (ETH_HDR_LEN + ntohs(ip_hdr->ip_len)))
        update_icmp_cksum(pkt_data, ip_hdr, icmp_hdr, &ip_hlb);

    free(ip_hdr);
    ip_hdr = NULL;

    /*
     * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
     * then copy icmp_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, icmp_hdr, ICMP_HDR_LEN);
    free(icmp_hdr);
    icmp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
        (void)*new_pkt_data--;

    /* no further editing support after ICMP hdr */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IP hdr) which covers ICMP hdr + data,
     * checksum for ICMP hdr corrected above,
     * while ICMP data is written to new_pkt_data in parse_ip()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETH_HDR_LEN + ip_hlb + ICMP_HDR_LEN);
}

void update_icmp_cksum(const uint8_t *pkt_data, struct ip *ip_hdr, struct icmphdr *icmp_hdr,
                       uint16_t *ip_hlb)
{
    uint8_t *icmpp; /* ICMP hdr + trailing data */
    uint16_t icmpp_len;
    int i;

    icmpp_len = ntohs(ip_hdr->ip_len) - *ip_hlb;

    icmpp = (uint8_t *)malloc(sizeof(uint8_t) * icmpp_len);
    if (icmpp == NULL)
        error("malloc(): cannot allocate memory for icmpp");
    memset(icmpp, 0, icmpp_len);

    /* clear checksum field */
    icmp_hdr->icmp_cksum = 0x0000;

    /* copy ICMP hdr from icmp_hdr into icmpp */
    memcpy(icmpp, icmp_hdr, ICMP_HDR_LEN);

    /* copy trailing data from payload_opt into icmpp */
    if (layer_opt == 4 && header_opt == ICMP && payload_len_opt > 0)
    {
        for (i = ICMP_HDR_LEN; i < (ICMP_HDR_LEN + payload_len_opt); i++)
            icmpp[i] = payload_opt[i - ICMP_HDR_LEN];
    }
    /* copy trailing data from payload_opt (payload after IP hdr) into icmpp */
    else if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
    {
        for (i = ICMP_HDR_LEN; i < payload_len_opt; i++)
            icmpp[i] = payload_opt[i];
    }
    /* copy trailing data from pkt_data into icmpp */
    else
    {
        for (i = ICMP_HDR_LEN; i < icmpp_len; i++)
            icmpp[i] = pkt_data[ETH_HDR_LEN + *ip_hlb + i];
    }

    /* recalculate checksum */
    icmp_hdr->icmp_cksum = cksum(icmpp, icmpp_len);

    free(icmpp);
    icmpp = NULL;
}

uint16_t parse_icmp6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                     struct ip6 *ip6_hdr)
{
    /*
     * ICMPv6 header (4 bytes)
     *  1. type (1 byte)
     *  2. code (1 byte)
     *  3. checksum (2 bytes)
     */
    struct icmp6hdr *icmp6_hdr;
    int i;

    /* do nothing if ICMPv6 hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN)
    {
        free(ip6_hdr);
        ip6_hdr = NULL;
        return (ETH_HDR_LEN + IP6_HDR_LEN);
    }

    icmp6_hdr = (struct icmp6hdr *)malloc(ICMP6_HDR_LEN);
    if (icmp6_hdr == NULL)
        error("malloc(): cannot allocate memory for icmp6_hdr");

    /*
     * we have payload which covers ICMPv6 hdr + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
    {
        /*
         * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
         * then copy ICMPv6 hdr from new_pkt_data into icmp6_hdr
         * and reset pointer to the beginning of new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
            (void)*new_pkt_data++;

        memcpy(icmp6_hdr, new_pkt_data, ICMP6_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
            (void)*new_pkt_data--;
    }
    else
    {
        /*
         * go pass Ethernet hdr and IPv6 hdr in pkt_data
         * then copy ICMPv6 hdr from pkt_data into icmp6_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETH_HDR_LEN + IP6_HDR_LEN))
            (void)*pkt_data++;

        memcpy(icmp6_hdr, pkt_data, ICMP6_HDR_LEN);

        i = 0;
        while (i++ < (ETH_HDR_LEN + IP6_HDR_LEN))
            (void)*pkt_data--;

        /* we are editing ICMPv6 hdr */
        if (header_opt == ICMP6)
        {
            /* overwrite type */
            if (icmp6opt->icmp6_type_flag)
                icmp6_hdr->icmp6_type = icmp6opt->icmp6_type;

            /* overwrite code */
            if (icmp6opt->icmp6_code_flag)
                icmp6_hdr->icmp6_code = icmp6opt->icmp6_code;
        }

        /* we are going to copy up to layer 4 only */
        if (layer_opt == 4)
        {
            /*
             * we are editing ICMPv6 hdr and we have payload,
             * attach the payload first before checksum calculation
             */
            if (header_opt == ICMP6 && payload_len_opt > 0)
            {
                /* truncate payload if it is too large */
                if ((payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN) > ETH_MAX_LEN)
                    payload_len_opt -=
                        (payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN) - ETH_MAX_LEN;

                /*
                 * go pass pcap hdr, Ethernet hdr, IPv6 hdr and ICMPv6 hdr in new_pkt_data
                 * then copy payload_opt into new_pkt_data
                 * and reset pointer to the beginning of new_pkt_data
                 */
                i = 0;
                while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN)
                    (void)*new_pkt_data++;

                memcpy(new_pkt_data, payload_opt, payload_len_opt);

                i = 0;
                while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN)
                    (void)*new_pkt_data--;

                header->caplen = header->len =
                    ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN + payload_len_opt;
            }
            else
                header->caplen = header->len = ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN;

            /* update IPv6 payload length */
            ip6_hdr->ip6_plen = htons(header->caplen - ETH_HDR_LEN);
            write_ip6_hdr(new_pkt_data, ip6_hdr);
        }
    }

    /*
     * recalculate checksum for ICMPv6 hdr (cover IPv6 pseudo hdr + ICMPv6 hdr + trailing data)
     * if we have enough data
     */
    if (csum_opt && header->caplen >= (ETH_HDR_LEN + IP6_HDR_LEN + ntohs(ip6_hdr->ip6_plen)))
        update_icmp6_cksum(pkt_data, ip6_hdr, icmp6_hdr);

    free(ip6_hdr);
    ip6_hdr = NULL;

    /*
     * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
     * then copy icmp6_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, icmp6_hdr, ICMP6_HDR_LEN);
    free(icmp6_hdr);
    icmp6_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
        (void)*new_pkt_data--;

    /* no further editing support after ICMPv6 hdr */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IPv6 hdr) which covers ICMPv6 hdr + data,
     * checksum for ICMPv6 hdr corrected above,
     * while ICMPv6 data is written to new_pkt_data in parse_ip6()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETH_HDR_LEN + IP6_HDR_LEN + ICMP6_HDR_LEN);
}

void update_icmp6_cksum(const uint8_t *pkt_data, struct ip6 *ip6_hdr, struct icmp6hdr *icmp6_hdr)
{
    struct ip6pseudo *ip6p; /* IPv6 pseudo hdr */
    uint8_t *icmp6p;        /* IPv6 pseudo hdr + ICMPv6 hdr + trailing data */
    uint16_t icmp6p_len;
    int i;

    /* create IP pseudo hdr */
    ip6p = create_ip6pseudo(ip6_hdr);

    icmp6p_len = sizeof(struct ip6pseudo) + ntohs(ip6p->ip6pseudo_len);

    icmp6p = (uint8_t *)malloc(sizeof(uint8_t) * icmp6p_len);
    if (icmp6p == NULL)
        error("malloc(): cannot allocate memory for icmp6p");
    memset(icmp6p, 0, icmp6p_len);

    /* copy IPv6 pseudo hdr from ip6p into icmp6p */
    memcpy(icmp6p, ip6p, sizeof(struct ip6pseudo));
    free(ip6p);
    ip6p = NULL;

    /* go pass IPv6 pseudo hdr in icmp6p */
    i = 0;
    while (i++ < sizeof(struct ip6pseudo))
        (void)*icmp6p++;

    /* clear checksum field */
    icmp6_hdr->icmp6_cksum = 0x0000;

    /* copy ICMPv6 hdr from icmp6_hdr into icmp6p */
    memcpy(icmp6p, icmp6_hdr, ICMP6_HDR_LEN);

    /* reset pointer to the beginning of icmp6p */
    i = 0;
    while (i++ < sizeof(struct ip6pseudo))
        (void)*icmp6p--;

    /* copy trailing data from payload_opt into icmp6p */
    if (layer_opt == 4 && header_opt == ICMP6 && payload_len_opt > 0)
    {
        for (i = ICMP6_HDR_LEN; i < (icmp6p_len - sizeof(struct ip6pseudo)); i++)
            icmp6p[i + sizeof(struct ip6pseudo)] = payload_opt[i - ICMP6_HDR_LEN];
    }
    /* copy trailing data from payload_opt (payload after IPv6 hdr) into icmp6p */
    else if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
    {
        for (i = ICMP6_HDR_LEN; i < payload_len_opt; i++)
            icmp6p[i + sizeof(struct ip6pseudo)] = payload_opt[i];
    }
    /* copy trailing data from pkt_data into icmp6p */
    else
    {
        for (i = ICMP6_HDR_LEN; i < (icmp6p_len - sizeof(struct ip6pseudo)); i++)
            icmp6p[i + sizeof(struct ip6pseudo)] = pkt_data[ETH_HDR_LEN + IP6_HDR_LEN + i];
    }

    /* recalculate checksum */
    icmp6_hdr->icmp6_cksum = cksum(icmp6p, icmp6p_len);

    free(icmp6p);
    icmp6p = NULL;
}

uint16_t parse_tcp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                   struct ip *ip_hdr)
{
    /*
     * TCP header (20 bytes + optional X bytes for options)
     *  1. source port (2 bytes)
     *  2. destination port (2 bytes)
     *  3. sequence number (4 bytes)
     *  4. acknowledgment number (4 bytes)
     *  5. data offset (4 bits) - number of 32-bit segments in TCP header
     *  6. reserved (6 bits)
     *  7. flags (6 bits)
     *  8. window (2 bytes)
     *  9. checksum (2 bytes)
     * 10. urgent pointer (2 bytes)
     * 11. options (X bytes)
     */
    struct tcphdr *tcp_hdr;
    uint8_t *tcp_o = NULL; /* options (X bytes) */
    uint16_t tcp_hlb;      /* TCP hdr length in bytes */
    uint16_t ip_hlb;       /* IP hdr length in bytes */
    uint16_t ip_fo;        /* IP fragment offset (number of 64-bit segments) */
    int i, j;

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* do nothing if TCP hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + ip_hlb + TCP_HDR_LEN)
    {
        free(ip_hdr);
        ip_hdr = NULL;
        return (ETH_HDR_LEN + ip_hlb);
    }

    tcp_hdr = (struct tcphdr *)malloc(TCP_HDR_LEN);
    if (tcp_hdr == NULL)
        error("malloc(): cannot allocate memory for tcp_hdr");

    /*
     * we have payload which covers TCP hdr + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
    {
        /*
         * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
         * then copy TCP hdr from new_pkt_data into tcp_hdr
         * and reset pointer to the beginning of new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
            (void)*new_pkt_data++;

        memcpy(tcp_hdr, new_pkt_data, TCP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
            (void)*new_pkt_data--;
    }
    else
    {
        /*
         * go pass Ethernet hdr and IP hdr in pkt_data
         * then copy TCP hdr from pkt_data into tcp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETH_HDR_LEN + ip_hlb))
            (void)*pkt_data++;

        memcpy(tcp_hdr, pkt_data, TCP_HDR_LEN);

        i = 0;
        while (i++ < (ETH_HDR_LEN + ip_hlb))
            (void)*pkt_data--;
    }

    tcp_hlb = tcp_hdr->th_off * 4; /* convert to bytes */

    /* have TCP options */
    if (tcp_hlb > TCP_HDR_LEN)
    {
        /* do nothing if TCP hdr with options is truncated */
        if (header->caplen < (ETH_HDR_LEN + ip_hlb + tcp_hlb))
        {
            free(ip_hdr);
            ip_hdr = NULL;
            free(tcp_hdr);
            tcp_hdr = NULL;
            return (ETH_HDR_LEN + ip_hlb);
        }

        tcp_o = (uint8_t *)malloc(sizeof(uint8_t) * (tcp_hlb - TCP_HDR_LEN));
        if (tcp_o == NULL)
            error("malloc(): cannot allocate memory for tcp_o");

        if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
        {
            /* copy TCP options from new_pkt_data into tcp_o */
            for (i = 0, j = TCP_HDR_LEN; i < (tcp_hlb - TCP_HDR_LEN); i++, j++)
                tcp_o[i] = new_pkt_data[PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + j];
        }
        else
        {
            /* copy TCP options from pkt_data into tcp_o */
            for (i = 0, j = TCP_HDR_LEN; i < (tcp_hlb - TCP_HDR_LEN); i++, j++)
                tcp_o[i] = pkt_data[ETH_HDR_LEN + ip_hlb + j];
        }
    }

    /* we are editing TCP hdr */
    if (header_opt == TCP)
        update_tcp_hdr(tcp_hdr);

    /* we are going to copy up to layer 4 only */
    if (layer_opt == 4)
    {
        /*
         * we are editing TCP hdr and we have payload,
         * attach the payload first before checksum calculation
         */
        if (header_opt == TCP && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN + ip_hlb + tcp_hlb) > ETH_MAX_LEN)
                payload_len_opt -= (payload_len_opt + ETH_HDR_LEN + ip_hlb + tcp_hlb) - ETH_MAX_LEN;

            /*
             * go pass pcap hdr, Ethernet hdr, IP hdr and TCP hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + tcp_hlb)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + tcp_hlb)
                (void)*new_pkt_data--;

            header->caplen = header->len = ETH_HDR_LEN + ip_hlb + tcp_hlb + payload_len_opt;
        }
        else
            header->caplen = header->len = ETH_HDR_LEN + ip_hlb + tcp_hlb;

        /* update IP total length */
        ip_hdr->ip_len = htons(header->caplen - ETH_HDR_LEN);

        /* go pass Ethernet hdr in pkt_data */
        i = 0;
        while (i++ < ETH_HDR_LEN)
            (void)*pkt_data++;

        /*
         * reuse parsing function for IP hdr
         * to update IP total length in new_pkt_data
         * and recalculate checksum for IP hdr if required
         */
        (void)parse_ip(pkt_data, new_pkt_data, header, ip_hdr, 1);

        /* reset pointer to the beginning of pkt_data */
        i = 0;
        while (i++ < ETH_HDR_LEN)
            (void)*pkt_data--;
    }

    /* we have no support for checksum calculation for fragmented packet */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /*
     * recalculate checksum for TCP hdr (cover IP pseudo hdr + TCP hdr + trailing data)
     * if we have enough data
     */
    if (csum_opt && ip_fo == 0 && header->caplen >= (ETH_HDR_LEN + ntohs(ip_hdr->ip_len)))
        update_tcp_cksum(pkt_data, ip_hdr, tcp_hdr, &ip_hlb, &tcp_hlb, tcp_o);

    free(ip_hdr);
    ip_hdr = NULL;

    /*
     * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
     * then copy tcp_hdr and tcp_o (if exist) into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, tcp_hdr, TCP_HDR_LEN);
    free(tcp_hdr);
    tcp_hdr = NULL;

    /* have TCP options */
    if (tcp_hlb > TCP_HDR_LEN)
    {
        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*new_pkt_data++;

        memcpy(new_pkt_data, tcp_o, tcp_hlb - TCP_HDR_LEN);
        free(tcp_o);
        tcp_o = NULL;

        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*new_pkt_data--;
    }

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
        (void)*new_pkt_data--;

    /* no further editing support after TCP hdr */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IP hdr) which covers TCP hdr + data,
     * checksum for TCP hdr corrected above,
     * while TCP data is written to new_pkt_data in parse_ip()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETH_HDR_LEN + ip_hlb + tcp_hlb);
}

void update_tcp_cksum(const uint8_t *pkt_data, struct ip *ip_hdr, struct tcphdr *tcp_hdr,
                      uint16_t *ip_hlb, uint16_t *tcp_hlb, uint8_t *tcp_o)
{
    struct ippseudo *ipp; /* IP pseudo hdr */
    uint8_t *tcpp;        /* IP pseudo hdr + TCP hdr (with options if exist) + trailing data */
    uint16_t tcpp_len;
    int i;

    /* create IP pseudo hdr */
    ipp = create_ippseudo(ip_hdr, ip_hlb);

    tcpp_len = sizeof(struct ippseudo) + ntohs(ipp->ippseudo_len);

    tcpp = (uint8_t *)malloc(sizeof(uint8_t) * tcpp_len);
    if (tcpp == NULL)
        error("malloc(): cannot allocate memory for tcpp");
    memset(tcpp, 0, tcpp_len);

    /* copy IP pseudo hdr from ipp into tcpp */
    memcpy(tcpp, ipp, sizeof(struct ippseudo));
    free(ipp);
    ipp = NULL;

    /* go pass IP pseudo hdr in tcpp */
    i = 0;
    while (i++ < sizeof(struct ippseudo))
        (void)*tcpp++;

    /* clear checksum field */
    tcp_hdr->th_sum = 0x0000;

    /* copy TCP hdr from tcp_hdr into tcpp */
    memcpy(tcpp, tcp_hdr, TCP_HDR_LEN);

    /*
     * have TCP options,
     * go pass TCP hdr in tcpp
     * then copy tcp_o into tcpp
     * and reset pointer of tcpp to go pass IP pseudo hdr only
     */
    if (*tcp_hlb > TCP_HDR_LEN)
    {
        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*tcpp++;

        memcpy(tcpp, tcp_o, *tcp_hlb - TCP_HDR_LEN);

        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*tcpp--;
    }

    /* reset pointer to the beginning of tcpp */
    i = 0;
    while (i++ < sizeof(struct ippseudo))
        (void)*tcpp--;

    /* copy trailing data from payload_opt into tcpp */
    if (layer_opt == 4 && header_opt == TCP && payload_len_opt > 0)
    {
        for (i = *tcp_hlb; i < (tcpp_len - sizeof(struct ippseudo)); i++)
            tcpp[i + sizeof(struct ippseudo)] = payload_opt[i - *tcp_hlb];
    }
    /* copy trailing data from payload_opt (payload after IP hdr) into tcpp */
    else if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
    {
        for (i = *tcp_hlb; i < payload_len_opt; i++)
            tcpp[i + sizeof(struct ippseudo)] = payload_opt[i];
    }
    /* copy trailing data from pkt_data into tcpp */
    else
    {
        for (i = *tcp_hlb; i < (tcpp_len - sizeof(struct ippseudo)); i++)
            tcpp[i + sizeof(struct ippseudo)] = pkt_data[ETH_HDR_LEN + *ip_hlb + i];
    }

    /* recalculate checksum */
    tcp_hdr->th_sum = cksum(tcpp, tcpp_len);

    free(tcpp);
    tcpp = NULL;
}

uint16_t parse_tcp6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                    struct ip6 *ip6_hdr)
{
    /*
     * TCP header (20 bytes + optional X bytes for options)
     *  1. source port (2 bytes)
     *  2. destination port (2 bytes)
     *  3. sequence number (4 bytes)
     *  4. acknowledgment number (4 bytes)
     *  5. data offset (4 bits) - number of 32-bit segments in TCP header
     *  6. reserved (6 bits)
     *  7. flags (6 bits)
     *  8. window (2 bytes)
     *  9. checksum (2 bytes)
     * 10. urgent pointer (2 bytes)
     * 11. options (X bytes)
     */
    struct tcphdr *tcp_hdr;
    uint8_t *tcp_o = NULL; /* options (X bytes) */
    uint16_t tcp_hlb;      /* TCP hdr length in bytes */
    int i, j;

    /* do nothing if TCP hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + IP6_HDR_LEN + TCP_HDR_LEN)
    {
        free(ip6_hdr);
        ip6_hdr = NULL;
        return (ETH_HDR_LEN + IP6_HDR_LEN);
    }

    tcp_hdr = (struct tcphdr *)malloc(TCP_HDR_LEN);
    if (tcp_hdr == NULL)
        error("malloc(): cannot allocate memory for tcp_hdr");

    /*
     * we have payload which covers TCP hdr + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
    {
        /*
         * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
         * then copy TCP hdr from new_pkt_data into tcp_hdr
         * and reset pointer to the beginning of new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
            (void)*new_pkt_data++;

        memcpy(tcp_hdr, new_pkt_data, TCP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
            (void)*new_pkt_data--;
    }
    else
    {
        /*
         * go pass Ethernet hdr and IPv6 hdr in pkt_data
         * then copy TCP hdr from pkt_data into tcp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETH_HDR_LEN + IP6_HDR_LEN))
            (void)*pkt_data++;

        memcpy(tcp_hdr, pkt_data, TCP_HDR_LEN);

        i = 0;
        while (i++ < (ETH_HDR_LEN + IP6_HDR_LEN))
            (void)*pkt_data--;
    }

    tcp_hlb = tcp_hdr->th_off * 4; /* convert to bytes */

    /* have TCP options */
    if (tcp_hlb > TCP_HDR_LEN)
    {
        /* do nothing if TCP hdr with options is truncated */
        if (header->caplen < (ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb))
        {
            free(ip6_hdr);
            ip6_hdr = NULL;
            free(tcp_hdr);
            tcp_hdr = NULL;
            return (ETH_HDR_LEN + IP6_HDR_LEN);
        }

        tcp_o = (uint8_t *)malloc(sizeof(uint8_t) * (tcp_hlb - TCP_HDR_LEN));
        if (tcp_o == NULL)
            error("malloc(): cannot allocate memory for tcp_o");

        if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
        {
            /* copy TCP options from new_pkt_data into tcp_o */
            for (i = 0, j = TCP_HDR_LEN; i < (tcp_hlb - TCP_HDR_LEN); i++, j++)
                tcp_o[i] = new_pkt_data[PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + j];
        }
        else
        {
            /* copy TCP options from pkt_data into tcp_o */
            for (i = 0, j = TCP_HDR_LEN; i < (tcp_hlb - TCP_HDR_LEN); i++, j++)
                tcp_o[i] = pkt_data[ETH_HDR_LEN + IP6_HDR_LEN + j];
        }
    }

    /* we are editing TCP hdr */
    if (header_opt == TCP)
        update_tcp_hdr(tcp_hdr);

    /* we are going to copy up to layer 4 only */
    if (layer_opt == 4)
    {
        /*
         * we are editing TCP hdr and we have payload,
         * attach the payload first before checksum calculation
         */
        if (header_opt == TCP && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb) > ETH_MAX_LEN)
                payload_len_opt -=
                    (payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb) - ETH_MAX_LEN;

            /*
             * go pass pcap hdr, Ethernet hdr, IPv6 hdr and TCP hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb)
                (void)*new_pkt_data--;

            header->caplen = header->len = ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb + payload_len_opt;
        }
        else
            header->caplen = header->len = ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb;

        /* update IPv6 payload length */
        ip6_hdr->ip6_plen = htons(header->caplen - (ETH_HDR_LEN + IP6_HDR_LEN));
        write_ip6_hdr(new_pkt_data, ip6_hdr);
    }

    /*
     * recalculate checksum for TCP hdr (cover IPv6 pseudo hdr + TCP hdr + trailing data)
     * if we have enough data
     */
    if (csum_opt && header->caplen >= (ETH_HDR_LEN + IP6_HDR_LEN + ntohs(ip6_hdr->ip6_plen)))
        update_tcp6_cksum(pkt_data, ip6_hdr, tcp_hdr, &tcp_hlb, tcp_o);

    free(ip6_hdr);
    ip6_hdr = NULL;

    /*
     * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
     * then copy tcp_hdr and tcp_o (if exist) into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, tcp_hdr, TCP_HDR_LEN);
    free(tcp_hdr);
    tcp_hdr = NULL;

    /* have TCP options */
    if (tcp_hlb > TCP_HDR_LEN)
    {
        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*new_pkt_data++;

        memcpy(new_pkt_data, tcp_o, tcp_hlb - TCP_HDR_LEN);
        free(tcp_o);
        tcp_o = NULL;

        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*new_pkt_data--;
    }

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
        (void)*new_pkt_data--;

    /* no further editing support after TCP hdr */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IPv6 hdr) which covers TCP hdr + data,
     * checksum for TCP hdr corrected above,
     * while TCP data is written to new_pkt_data in parse_ip6()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETH_HDR_LEN + IP6_HDR_LEN + tcp_hlb);
}

void update_tcp6_cksum(const uint8_t *pkt_data, struct ip6 *ip6_hdr, struct tcphdr *tcp_hdr,
                       uint16_t *tcp_hlb, uint8_t *tcp_o)
{
    struct ip6pseudo *ip6p; /* IPv6 pseudo hdr */
    uint8_t *tcpp;          /* IPv6 pseudo hdr + TCP hdr (with options if exist) + trailing data */
    uint16_t tcpp_len;
    int i;

    /* create IP pseudo hdr */
    ip6p = create_ip6pseudo(ip6_hdr);

    tcpp_len = sizeof(struct ip6pseudo) + ntohs(ip6p->ip6pseudo_len);

    tcpp = (uint8_t *)malloc(sizeof(uint8_t) * tcpp_len);
    if (tcpp == NULL)
        error("malloc(): cannot allocate memory for tcpp");
    memset(tcpp, 0, tcpp_len);

    /* copy IPv6 pseudo hdr from ipp into tcpp */
    memcpy(tcpp, ip6p, sizeof(struct ip6pseudo));
    free(ip6p);
    ip6p = NULL;

    /* go pass IPv6 pseudo hdr in tcpp */
    i = 0;
    while (i++ < sizeof(struct ip6pseudo))
        (void)*tcpp++;

    /* clear checksum field */
    tcp_hdr->th_sum = 0x0000;

    /* copy TCP hdr from tcp_hdr into tcpp */
    memcpy(tcpp, tcp_hdr, TCP_HDR_LEN);

    /*
     * have TCP options,
     * go pass TCP hdr in tcpp
     * then copy tcp_o into tcpp
     * and reset pointer of tcpp to go pass IPv6 pseudo hdr only
     */
    if (*tcp_hlb > TCP_HDR_LEN)
    {
        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*tcpp++;

        memcpy(tcpp, tcp_o, *tcp_hlb - TCP_HDR_LEN);

        i = 0;
        while (i++ < TCP_HDR_LEN)
            (void)*tcpp--;
    }

    /* reset pointer to the beginning of tcpp */
    i = 0;
    while (i++ < sizeof(struct ip6pseudo))
        (void)*tcpp--;

    /* copy trailing data from payload_opt into tcpp */
    if (layer_opt == 4 && header_opt == TCP && payload_len_opt > 0)
    {
        for (i = *tcp_hlb; i < (tcpp_len - sizeof(struct ip6pseudo)); i++)
            tcpp[i + sizeof(struct ip6pseudo)] = payload_opt[i - *tcp_hlb];
    }
    /* copy trailing data from payload_opt (payload after IPv6 hdr) into tcpp */
    else if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
    {
        for (i = *tcp_hlb; i < payload_len_opt; i++)
            tcpp[i + sizeof(struct ip6pseudo)] = payload_opt[i];
    }
    /* copy trailing data from pkt_data into tcpp */
    else
    {
        for (i = *tcp_hlb; i < (tcpp_len - sizeof(struct ip6pseudo)); i++)
            tcpp[i + sizeof(struct ip6pseudo)] = pkt_data[ETH_HDR_LEN + IP6_HDR_LEN + i];
    }

    /* recalculate checksum */
    tcp_hdr->th_sum = cksum(tcpp, tcpp_len);

    free(tcpp);
    tcpp = NULL;
}

void update_tcp_hdr(struct tcphdr *tcp_hdr)
{
    /* overwrite source port */
    if (tcpopt->th_sport_flag == FIELD_SET)
        tcp_hdr->th_sport = htons(tcpopt->th_old_sport);
    else if (tcpopt->th_sport_flag == FIELD_REPLACE &&
             tcp_hdr->th_sport == htons(tcpopt->th_old_sport))
        tcp_hdr->th_sport = htons(tcpopt->th_new_sport);
    else if (tcpopt->th_sport_flag == FIELD_SET_RAND ||
             (tcpopt->th_sport_flag == FIELD_REPLACE_RAND &&
              tcp_hdr->th_sport == htons(tcpopt->th_old_sport)))
        tcp_hdr->th_sport = htons(get_random_number(UINT16_MAX));

    /* overwrite destination port */
    if (tcpopt->th_dport_flag == FIELD_SET)
        tcp_hdr->th_dport = htons(tcpopt->th_old_dport);
    else if (tcpopt->th_dport_flag == FIELD_REPLACE &&
             tcp_hdr->th_dport == htons(tcpopt->th_old_dport))
        tcp_hdr->th_dport = htons(tcpopt->th_new_dport);
    else if (tcpopt->th_dport_flag == FIELD_SET_RAND ||
             (tcpopt->th_dport_flag == FIELD_REPLACE_RAND &&
              tcp_hdr->th_dport == htons(tcpopt->th_old_dport)))
        tcp_hdr->th_dport = htons(get_random_number(UINT16_MAX));

    /* overwrite sequence number */
    if (tcpopt->th_seq_flag == FIELD_SET)
        tcp_hdr->th_seq = htonl(tcpopt->th_old_seq);
    else if (tcpopt->th_seq_flag == FIELD_REPLACE && tcp_hdr->th_seq == htonl(tcpopt->th_old_seq))
        tcp_hdr->th_seq = htonl(tcpopt->th_new_seq);
    else if (tcpopt->th_seq_flag == FIELD_SET_RAND ||
             (tcpopt->th_seq_flag == FIELD_REPLACE_RAND &&
              tcp_hdr->th_seq == htonl(tcpopt->th_old_seq)))
        tcp_hdr->th_seq = htonl(get_random_number(UINT32_MAX));

    /* overwrite acknowledgment number */
    if (tcpopt->th_ack_flag == FIELD_SET)
        tcp_hdr->th_ack = htonl(tcpopt->th_old_ack);
    else if (tcpopt->th_ack_flag == FIELD_REPLACE && tcp_hdr->th_ack == htonl(tcpopt->th_old_ack))
        tcp_hdr->th_ack = htonl(tcpopt->th_new_ack);
    else if (tcpopt->th_ack_flag == FIELD_SET_RAND ||
             (tcpopt->th_ack_flag == FIELD_REPLACE_RAND &&
              tcp_hdr->th_ack == htonl(tcpopt->th_old_ack)))
        tcp_hdr->th_ack = htonl(get_random_number(UINT32_MAX));

    /* overwrite flags */
    if (tcpopt->th_flags_flag)
        tcp_hdr->th_flags = ((tcpopt->th_flag_c ? TH_CWR : 0) | (tcpopt->th_flag_e ? TH_ECE : 0) |
                             (tcpopt->th_flag_u ? TH_URG : 0) | (tcpopt->th_flag_a ? TH_ACK : 0) |
                             (tcpopt->th_flag_p ? TH_PUSH : 0) | (tcpopt->th_flag_r ? TH_RST : 0) |
                             (tcpopt->th_flag_s ? TH_SYN : 0) | (tcpopt->th_flag_f ? TH_FIN : 0));

    /* overwrite window size */
    if (tcpopt->th_win_flag)
        tcp_hdr->th_win = htons(tcpopt->th_win);

    /* overwrite urgent pointer */
    if (tcpopt->th_urp_flag)
        tcp_hdr->th_urp = htons(tcpopt->th_urp);
}

uint16_t parse_udp(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                   struct ip *ip_hdr)
{
    /*
     * UDP header (8 bytes)
     *  1. source port (2 bytes)
     *  2. destination port (2 bytes)
     *  3. length (2 bytes)
     *  4. checksum (2 bytes)
     */
    struct udphdr *udp_hdr;
    uint16_t ip_hlb; /* IP hdr length in bytes */
    uint16_t ip_fo;  /* IP fragment offset (number of 64-bit segments) */
    int i;

    ip_hlb = ip_hdr->ip_hl * 4; /* convert to bytes */

    /* do nothing if UDP hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN)
    {
        free(ip_hdr);
        ip_hdr = NULL;
        return (ETH_HDR_LEN + ip_hlb);
    }

    udp_hdr = (struct udphdr *)malloc(UDP_HDR_LEN);
    if (udp_hdr == NULL)
        error("malloc(): cannot allocate memory for udp_hdr");

    /*
     * we have payload which covers UDP hdr + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
    {
        /*
         * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
         * then copy UDP hdr from new_pkt_data into udp_hdr
         * and reset pointer to the beginning of new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
            (void)*new_pkt_data++;

        memcpy(udp_hdr, new_pkt_data, UDP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
            (void)*new_pkt_data--;
    }
    else
    {
        /*
         * go pass Ethernet hdr and IP hdr in pkt_data
         * then copy UDP hdr from pkt_data into udp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETH_HDR_LEN + ip_hlb))
            (void)*pkt_data++;

        memcpy(udp_hdr, pkt_data, UDP_HDR_LEN);

        i = 0;
        while (i++ < (ETH_HDR_LEN + ip_hlb))
            (void)*pkt_data--;
    }

    /* we are editing UDP hdr */
    if (header_opt == UDP)
        update_udp_hdr(udp_hdr);

    /* we are going to copy up to layer 4 only */
    if (layer_opt == 4)
    {
        /*
         * we are editing UDP hdr and we have payload,
         * attach the payload first before checksum calculation
         */
        if (header_opt == UDP && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN) > ETH_MAX_LEN)
                payload_len_opt -=
                    (payload_len_opt + ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN) - ETH_MAX_LEN;

            /*
             * go pass pcap hdr, Ethernet hdr, IP hdr and UDP hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN)
                (void)*new_pkt_data--;

            header->caplen = header->len = ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN;

        /* update UDP length */
        udp_hdr->uh_ulen = htons(header->caplen - (ETH_HDR_LEN + ip_hlb));

        /* update IP total length */
        ip_hdr->ip_len = htons(header->caplen - ETH_HDR_LEN);

        /* go pass Ethernet hdr in pkt_data */
        i = 0;
        while (i++ < ETH_HDR_LEN)
            (void)*pkt_data++;

        /*
         * reuse parsing function for IP hdr
         * to update IP total length in new_pkt_data
         * and recalculate checksum for IP hdr if required
         */
        (void)parse_ip(pkt_data, new_pkt_data, header, ip_hdr, 1);

        /* reset pointer to the beginning of pkt_data */
        i = 0;
        while (i++ < ETH_HDR_LEN)
            (void)*pkt_data--;
    }

    /* we have no support for checksum calculation for fragmented packet */
    ip_fo = ntohs(ip_hdr->ip_off) & IP_OFFMASK;

    /*
     * recalculate checksum for UDP hdr (cover IP pseudo hdr + UDP hdr + trailing data)
     * if we have enough data
     */
    if (csum_opt && ip_fo == 0 && header->caplen >= (ETH_HDR_LEN + ntohs(ip_hdr->ip_len)))
        update_udp_cksum(pkt_data, ip_hdr, udp_hdr, &ip_hlb);

    free(ip_hdr);
    ip_hdr = NULL;

    /*
     * go pass pcap hdr, Ethernet hdr and IP hdr in new_pkt_data
     * then copy udp_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, udp_hdr, UDP_HDR_LEN);
    free(udp_hdr);
    udp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + ip_hlb)
        (void)*new_pkt_data--;

    /* no further editing support after UDP hdr */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IP hdr) which covers UDP hdr + data,
     * checksum for UDP hdr corrected above,
     * while UDP data is written to new_pkt_data in parse_ip()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETH_HDR_LEN + ip_hlb + UDP_HDR_LEN);
}

void update_udp_cksum(const uint8_t *pkt_data, struct ip *ip_hdr, struct udphdr *udp_hdr,
                      uint16_t *ip_hlb)
{
    struct ippseudo *ipp; /* IP pseudo hdr */
    uint8_t *udpp;        /* IP pseudo hdr + UDP hdr + trailing data */
    uint16_t udpp_len;
    int i;

    /* create IP pseudo hdr */
    ipp = create_ippseudo(ip_hdr, ip_hlb);

    udpp_len = sizeof(struct ippseudo) + ntohs(ipp->ippseudo_len);

    udpp = (uint8_t *)malloc(sizeof(uint8_t) * udpp_len);
    if (udpp == NULL)
        error("malloc(): cannot allocate memory for udpp");
    memset(udpp, 0, udpp_len);

    /* copy IP pseudo hdr from ipp into udpp */
    memcpy(udpp, ipp, sizeof(struct ippseudo));
    free(ipp);
    ipp = NULL;

    /* go pass IP pseudo hdr in udpp */
    i = 0;
    while (i++ < sizeof(struct ippseudo))
        (void)*udpp++;

    /* clear checksum field */
    udp_hdr->uh_sum = 0x0000;

    /* copy UDP hdr from udp_hdr into udpp */
    memcpy(udpp, udp_hdr, UDP_HDR_LEN);

    /* reset pointer to the beginning of udpp */
    i = 0;
    while (i++ < sizeof(struct ippseudo))
        (void)*udpp--;

    /* copy trailing data from payload_opt into udpp */
    if (layer_opt == 4 && header_opt == UDP && payload_len_opt > 0)
    {
        for (i = UDP_HDR_LEN; i < (udpp_len - sizeof(struct ippseudo)); i++)
            udpp[i + sizeof(struct ippseudo)] = payload_opt[i - UDP_HDR_LEN];
    }
    /* copy trailing data from payload_opt (payload after IP hdr) into udpp */
    else if (layer_opt == 3 && header_opt == IP && payload_len_opt > 0)
    {
        for (i = UDP_HDR_LEN; i < payload_len_opt; i++)
            udpp[i + sizeof(struct ippseudo)] = payload_opt[i];
    }
    /* copy trailing data from pkt_data into udpp */
    else
    {
        for (i = UDP_HDR_LEN; i < (udpp_len - sizeof(struct ippseudo)); i++)
            udpp[i + sizeof(struct ippseudo)] = pkt_data[ETH_HDR_LEN + *ip_hlb + i];
    }

    /* recalculate checksum */
    udp_hdr->uh_sum = cksum(udpp, udpp_len);

    free(udpp);
    udpp = NULL;
}

uint16_t parse_udp6(const uint8_t *pkt_data, uint8_t *new_pkt_data, struct pcap_sf_pkthdr *header,
                    struct ip6 *ip6_hdr)
{
    /*
     * UDP header (8 bytes)
     *  1. source port (2 bytes)
     *  2. destination port (2 bytes)
     *  3. length (2 bytes)
     *  4. checksum (2 bytes)
     */
    struct udphdr *udp_hdr;
    int i;

    /* do nothing if UDP hdr is truncated */
    if (header->caplen < ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN)
    {
        free(ip6_hdr);
        ip6_hdr = NULL;
        return (ETH_HDR_LEN + IP6_HDR_LEN);
    }

    udp_hdr = (struct udphdr *)malloc(UDP_HDR_LEN);
    if (udp_hdr == NULL)
        error("malloc(): cannot allocate memory for udp_hdr");

    /*
     * we have payload which covers UDP hdr + data,
     * use that payload instead of pkt_data
     */
    if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
    {
        /*
         * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
         * then copy UDP hdr from new_pkt_data into udp_hdr
         * and reset pointer to the beginning of new_pkt_data
         */
        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
            (void)*new_pkt_data++;

        memcpy(udp_hdr, new_pkt_data, UDP_HDR_LEN);

        i = 0;
        while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
            (void)*new_pkt_data--;
    }
    else
    {
        /*
         * go pass Ethernet hdr and IPv6 hdr in pkt_data
         * then copy UDP hdr from pkt_data into udp_hdr
         * and reset pointer to the beginning of pkt_data
         */
        i = 0;
        while (i++ < (ETH_HDR_LEN + IP6_HDR_LEN))
            (void)*pkt_data++;

        memcpy(udp_hdr, pkt_data, UDP_HDR_LEN);

        i = 0;
        while (i++ < (ETH_HDR_LEN + IP6_HDR_LEN))
            (void)*pkt_data--;
    }

    /* we are editing UDP hdr */
    if (header_opt == UDP)
        update_udp_hdr(udp_hdr);

    /* we are going to copy up to layer 4 only */
    if (layer_opt == 4)
    {
        /*
         * we are editing UDP hdr and we have payload,
         * attach the payload first before checksum calculation
         */
        if (header_opt == UDP && payload_len_opt > 0)
        {
            /* truncate payload if it is too large */
            if ((payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN) > ETH_MAX_LEN)
                payload_len_opt -=
                    (payload_len_opt + ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN) - ETH_MAX_LEN;

            /*
             * go pass pcap hdr, Ethernet hdr, IPv6 hdr and UDP hdr in new_pkt_data
             * then copy payload_opt into new_pkt_data
             * and reset pointer to the beginning of new_pkt_data
             */
            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN)
                (void)*new_pkt_data++;

            memcpy(new_pkt_data, payload_opt, payload_len_opt);

            i = 0;
            while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN)
                (void)*new_pkt_data--;

            header->caplen = header->len =
                ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN + payload_len_opt;
        }
        else
            header->caplen = header->len = ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN;

        /* update UDP length and IPv6 payload length */
        udp_hdr->uh_ulen = ip6_hdr->ip6_plen = htons(header->caplen - (ETH_HDR_LEN + IP6_HDR_LEN));
        write_ip6_hdr(new_pkt_data, ip6_hdr);
    }

    /*
     * recalculate checksum for UDP hdr (cover IPv6 pseudo hdr + UDP hdr + trailing data)
     * if we have enough data
     */
    if (csum_opt && header->caplen >= (ETH_HDR_LEN + IP6_HDR_LEN + ntohs(ip6_hdr->ip6_plen)))
        update_udp6_cksum(pkt_data, ip6_hdr, udp_hdr);

    free(ip6_hdr);
    ip6_hdr = NULL;

    /*
     * go pass pcap hdr, Ethernet hdr and IPv6 hdr in new_pkt_data
     * then copy udp_hdr into new_pkt_data
     * and reset pointer to the beginning of new_pkt_data
     */
    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
        (void)*new_pkt_data++;

    memcpy(new_pkt_data, udp_hdr, UDP_HDR_LEN);
    free(udp_hdr);
    udp_hdr = NULL;

    i = 0;
    while (i++ < PCAP_HDR_LEN + ETH_HDR_LEN + IP6_HDR_LEN)
        (void)*new_pkt_data--;

    /* no further editing support after UDP hdr */
    if (layer_opt == 4)
        return (header->caplen);
    /*
     * we have written payload_opt (payload after IPv6 hdr) which covers UDP hdr + data,
     * checksum for UDP hdr corrected above,
     * while UDP data is written to new_pkt_data in parse_ip6()
     */
    else if (layer_opt == 3)
        return (header->caplen);
    else
        return (ETH_HDR_LEN + IP6_HDR_LEN + UDP_HDR_LEN);
}

void update_udp6_cksum(const uint8_t *pkt_data, struct ip6 *ip6_hdr, struct udphdr *udp_hdr)
{
    struct ip6pseudo *ip6p; /* IPv6 pseudo hdr */
    uint8_t *udpp;          /* IPv6 pseudo hdr + UDP hdr + trailing data */
    uint16_t udpp_len;
    int i;

    /* create IPv6 pseudo hdr */
    ip6p = create_ip6pseudo(ip6_hdr);

    udpp_len = sizeof(struct ip6pseudo) + ntohs(ip6p->ip6pseudo_len);

    udpp = (uint8_t *)malloc(sizeof(uint8_t) * udpp_len);
    if (udpp == NULL)
        error("malloc(): cannot allocate memory for udpp");
    memset(udpp, 0, udpp_len);

    /* copy IPv6 pseudo hdr from ipp into udpp */
    memcpy(udpp, ip6p, sizeof(struct ip6pseudo));
    free(ip6p);
    ip6p = NULL;

    /* go pass IPv6 pseudo hdr in udpp */
    i = 0;
    while (i++ < sizeof(struct ip6pseudo))
        (void)*udpp++;

    /* clear checksum field */
    udp_hdr->uh_sum = 0x0000;

    /* copy UDP hdr from udp_hdr into udpp */
    memcpy(udpp, udp_hdr, UDP_HDR_LEN);

    /* reset pointer to the beginning of udpp */
    i = 0;
    while (i++ < sizeof(struct ip6pseudo))
        (void)*udpp--;

    /* copy trailing data from payload_opt into udpp */
    if (layer_opt == 4 && header_opt == UDP && payload_len_opt > 0)
    {
        for (i = UDP_HDR_LEN; i < (udpp_len - sizeof(struct ip6pseudo)); i++)
            udpp[i + sizeof(struct ip6pseudo)] = payload_opt[i - UDP_HDR_LEN];
    }
    /* copy trailing data from payload_opt (payload after IPv6 hdr) into udpp */
    else if (layer_opt == 3 && header_opt == IP6 && payload_len_opt > 0)
    {
        for (i = UDP_HDR_LEN; i < payload_len_opt; i++)
            udpp[i + sizeof(struct ip6pseudo)] = payload_opt[i];
    }
    /* copy trailing data from pkt_data into udpp */
    else
    {
        for (i = UDP_HDR_LEN; i < (udpp_len - sizeof(struct ip6pseudo)); i++)
            udpp[i + sizeof(struct ip6pseudo)] = pkt_data[ETH_HDR_LEN + IP6_HDR_LEN + i];
    }

    /* recalculate checksum */
    udp_hdr->uh_sum = cksum(udpp, udpp_len);

    free(udpp);
    udpp = NULL;
}

void update_udp_hdr(struct udphdr *udp_hdr)
{
    /* overwrite source port */
    if (udpopt->uh_sport_flag == FIELD_SET)
        udp_hdr->uh_sport = htons(udpopt->uh_old_sport);
    else if (udpopt->uh_sport_flag == FIELD_REPLACE &&
             udp_hdr->uh_sport == htons(udpopt->uh_old_sport))
        udp_hdr->uh_sport = htons(udpopt->uh_new_sport);
    else if (udpopt->uh_sport_flag == FIELD_SET_RAND ||
             (udpopt->uh_sport_flag == FIELD_REPLACE_RAND &&
              udp_hdr->uh_sport == htons(udpopt->uh_old_sport)))
        udp_hdr->uh_sport = htons(get_random_number(UINT16_MAX));

    /* overwrite destination port */
    if (udpopt->uh_dport_flag == FIELD_SET)
        udp_hdr->uh_dport = htons(udpopt->uh_old_dport);
    else if (udpopt->uh_dport_flag == FIELD_REPLACE &&
             udp_hdr->uh_dport == htons(udpopt->uh_old_dport))
        udp_hdr->uh_dport = htons(udpopt->uh_new_dport);
    else if (udpopt->uh_dport_flag == FIELD_SET_RAND ||
             (udpopt->uh_dport_flag == FIELD_REPLACE_RAND &&
              udp_hdr->uh_dport == htons(udpopt->uh_old_dport)))
        udp_hdr->uh_dport = htons(get_random_number(UINT16_MAX));
}

void set_random_eth_addr(uint8_t *eth_addr)
{
    uint64_t r = tinymt64_generate_uint64(&tinymt); /* 8 segments of random 8 bits */

    for (uint8_t i = 0; i < ETH_ADDR_LEN; i++)
    {
        eth_addr[i] = (uint8_t)(r & 0xff);
        r >>= 8; /* use next segment of random 8 bits */
    }
}

void set_random_in_addr(struct in_addr *addr, struct in_addr_opt *opt)
{
    uint8_t rem_bits = opt->rand_bits;              /* remaining last/right bits to randomize */
    uint64_t r = tinymt64_generate_uint64(&tinymt); /* 8 segments of random 8 bits */

    for (uint8_t i = 0; i < 4; i++) /* loop 4 octets */
    {
        rem_bits -= (rem_bits > 8) ? 8 : rem_bits;

        opt->new.s_addr = opt->new.s_addr ^ ((opt->new.s_addr ^ r) & ~opt->netmask.s_addr);

        if (rem_bits == 0)
            break;

        r >>= 8; /* use next segment of random 8 bits */
    }
    memcpy(addr, &opt->new, sizeof(struct in_addr));
}

void set_random_in6_addr(struct in6_addr *addr, struct in6_addr_opt *opt)
{
    uint8_t rem_bits = opt->rand_bits;              /* remaining last/right bits to randomize */
    uint64_t r = tinymt64_generate_uint64(&tinymt); /* 8 segments of random 8 bits */

    for (uint8_t i = 15; i >= 0; i--) /* loop 16 octets starting from last octet */
    {
        rem_bits -= (rem_bits > 8) ? 8 : rem_bits;

        opt->new.s6_addr[i] =
            opt->new.s6_addr[i] ^ ((opt->new.s6_addr[i] ^ r) & ~opt->netmask.s6_addr[i]);

        if (rem_bits == 0)
            break;

        r >>= 8; /* use next segment of random 8 bits */

        /* exhausted all 8 segments, regenerate new segments of random 8 bits */
        if (i % 8 == 0)
            r = tinymt64_generate_uint64(&tinymt);
    }
    memcpy(addr, &opt->new, sizeof(struct in6_addr));
}

uint64_t get_random_number(uint64_t max_val)
{
    /* return uniformly distributed random number between 0 and max_val inclusive */
    return tinymt64_generate_double(&tinymt) * (max_val + 1);
}

struct ippseudo *create_ippseudo(struct ip *ip_hdr, uint16_t *ip_hlb)
{
    struct ippseudo *ipp = (struct ippseudo *)malloc(sizeof(struct ippseudo));
    if (ipp == NULL)
        error("malloc(): cannot allocate memory for ipp");

    memcpy(&ipp->ippseudo_src, &ip_hdr->ip_src, sizeof(struct in_addr));
    memcpy(&ipp->ippseudo_dst, &ip_hdr->ip_dst, sizeof(struct in_addr));
    ipp->ippseudo_pad = 0x00;
    ipp->ippseudo_p = ip_hdr->ip_p;
    ipp->ippseudo_len = htons(ntohs(ip_hdr->ip_len) - *ip_hlb);

    return ipp;
}

struct ip6pseudo *create_ip6pseudo(struct ip6 *ip6_hdr)
{
    struct ip6pseudo *ip6p = (struct ip6pseudo *)malloc(sizeof(struct ip6pseudo));
    if (ip6p == NULL)
        error("malloc(): cannot allocate memory for ip6p");
    memset(ip6p, 0, sizeof(struct ip6pseudo));

    memcpy(&ip6p->ip6pseudo_src, &ip6_hdr->ip6_src, sizeof(struct in6_addr));
    memcpy(&ip6p->ip6pseudo_dst, &ip6_hdr->ip6_dst, sizeof(struct in6_addr));
    ip6p->ip6pseudo_len = ip6_hdr->ip6_plen;
    ip6p->ip6pseudo_nxt = ip6_hdr->ip6_nxt;

    return ip6p;
}

/* Reference: rfc1071.txt */
uint16_t cksum(const void *cp, uint16_t len)
{
    const uint16_t *word_16 = cp; /* 16-bit word at a time */
    uint16_t rem = len;
    unsigned int sum = 0;

    /* add all 16-bit words */
    while (rem > 1)
    {
        sum += *word_16;
        word_16++;
        rem -= 2;
    }

    /* add last byte if len is odd */
    if (rem)
        sum += *(uint8_t *)word_16;

    /* fold 32-bit sum into 16 bits in network byte order */
    while (sum > 0xffff)
        sum = (sum >> 16) + (sum & 0xffff);

    /* one's complement the sum */
    return (uint16_t)(~sum);
}

void info(void)
{
    (void)putchar('\n');
    notice("%lu packets (%lu bytes) written", pkts, bytes);
}

void notice(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    (void)vprintf(fmt, ap);
    va_end(ap);

    if (*fmt)
    {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)puts("");
    }
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void error(const char *fmt, ...)
{
    va_list ap;
    (void)fprintf(stderr, "%s: ", program_name);
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    if (*fmt)
    {
        fmt += strlen(fmt);
        if (fmt[-1] != '\n')
            (void)fputc('\n', stderr);
    }
    exit(EXIT_FAILURE);
}

int eth_aton(const char *cp, uint8_t *eth_addr)
{
    int i;
    unsigned int o0, o1, o2, o3, o4, o5;

    i = sscanf(cp, "%x:%x:%x:%x:%x:%x", &o0, &o1, &o2, &o3, &o4, &o5);

    if (i != 6)
    {
        eth_addr = NULL;
        return 0;
    }

    eth_addr[0] = o0;
    eth_addr[1] = o1;
    eth_addr[2] = o2;
    eth_addr[3] = o3;
    eth_addr[4] = o4;
    eth_addr[5] = o5;
    return 1;
}

void usage(void)
{
    (void)fprintf(stderr,
                  "%s version %s, Copyright (C) 2006 - 2023 Addy Yeow <ayeowch@gmail.com>\n"
                  "%s\n"
                  "Usage: %s [-I input] [-O output] [-L layer] [-X payload] [-C]\n"
                  "                 [-M linktype] [-D offset] [-R range] [-S timeframe]\n"
                  "                 [-N repeat] [-G gaprange] [-P seed] [-T header]\n"
                  "                 [header-specific-options] [-h]\n"
                  "\nOptions:\n"
                  " -I input        Input pcap based trace file. Typically, input should be a\n"
                  "                 file path to a pcap based trace file. However, for\n"
                  "                 convenience, the following template names are also\n"
                  "                 accepted to load trace file from one of the built-in\n"
                  "                 templates:\n"
                  "                 eth    : Ethernet header\n"
                  "                 arp    : ARP header\n"
                  "                 ip     : IPv4 header\n"
                  "                 ip6    : IPv6 header\n"
                  "                 icmp   : ICMPv4 header\n"
                  "                 icmp6  : ICMPv6 header\n"
                  "                 tcp    : IPv4 TCP header\n"
                  "                 ip6tcp : IPv6 TCP header\n"
                  "                 udp    : IPv4 UDP header\n"
                  "                 ip6udp : IPv6 UDP header\n"
                  "                 Example: -I icmp\n"
                  " -O output       Output trace file.\n"
                  " -L layer        Copy up to the specified 'layer' and discard the remaining\n"
                  "                 data. Value for 'layer' must be either 2, 3, or 4 where\n"
                  "                 2 for Ethernet, 3 for ARP, IPv4, or IPv6, and 4 for ICMPv4,\n"
                  "                 ICMPv6, TCP, or UDP.\n"
                  " -X payload      Append 'payload' in hex digits to the end of each packet.\n"
                  "                 Example: -X 0302aad1\n"
                  "                 -X flag is ignored if -L and -T flag are not specified.\n"
                  " -C              Specify this flag to disable checksum correction.\n"
                  "                 Checksum correction is applicable for non-fragmented\n"
                  "                 supported packets only.\n"
                  " -M linktype     Replace the 'linktype' stored in the pcap file header.\n"
                  "                 Typically, value for 'linktype' is 1 for Ethernet.\n"
                  "                 Example: -M 12 (for raw IP), -M 51 (for PPPoE)\n"
                  " -D offset       Delete the specified byte 'offset' from each packet.\n"
                  "                 First byte (starting from link layer header) starts from 1.\n"
                  "                 -L, -X, -C and -T flag are ignored if -D flag is specified.\n"
                  "                 Example: -D 15-40, -D 10, or -D 18-9999\n"
                  " -R range        Save only the specified 'range' of packets.\n"
                  "                 Example: -R 5-21 or -R 9\n"
                  " -S timeframe    Save only the packets within the specified 'timeframe' with\n"
                  "                 up to one-second resolution using DD/MM/YYYY,HH:MM:SS as the\n"
                  "                 format for start and end time in 'timeframe'.\n"
                  "                 Example: -S 22/10/2006,21:47:35-24/10/2006,13:16:05\n"
                  "                 -S flag is evaluated after -R flag.\n"
                  " -N repeat       Duplicate packets from the 'input' trace file 'repeat'\n"
                  "                 times. Use this flag to create a stream of packets,\n"
                  "                 each with, for example, a random tcp sequence number, from\n"
                  "                 a 1-packet trace file.\n"
                  "                 Example: -N 100000\n"
                  "                 -N flag is evaluated after -R and -S flag.\n"
                  " -G gaprange     Apply inter-packet gap between packets in microseconds from\n"
                  "                 1 to (2^31 - 1). Values in 'gaprange' are inclusive and\n"
                  "                 selected randomly. A single value implies a fixed gap.\n"
                  "                 Example: -G 1000-10000 or -G 1000\n"
                  "                 -G flag is evaluated after -R, -S, and -N flag.\n"
                  " -P seed         Positive integer to seed the random number generator (RNG)\n"
                  "                 used, for example, to  generate random  port number.\n"
                  "                 If unset, current timestamp will be used as the RNG seed.\n"
                  "                 bittwiste uses Mersenne Twister for high-speed uniformly\n"
                  "                 distributed random number generation.\n"
                  " -T header       Edit only the specified 'header'. Possible keywords for\n"
                  "                 'header' are, eth, arp, ip, ip6, icmp, icmp6, tcp, or udp.\n"
                  "                 -T flag must appear last among the general options.\n"
                  " -h              Print version information and usage.\n"
                  " header-specific-options\n"
                  "                 See bittwiste manual page for header specific options.\n",
                  program_name, BITTWISTE_VERSION, pcap_lib_version(), program_name);
    exit(EXIT_SUCCESS);
}
