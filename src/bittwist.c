/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * bittwist - pcap based ethernet packet generator
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

#include "bittwist.h"
#include "token_bucket.h"

char *program_name;

int32_t thiszone; /* offset from GMT to local time in seconds */

char ebuf[PCAP_ERRBUF_SIZE]; /* pcap error buffer */

/* options */
int vflag = 0;           /* 1 = print timestamp, 2 = print timestamp and hex data */
int len = 0;             /* packet length to send (-1 = captured, 0 = on wire, or positive
                            value <= 1514) */
int pps = 0;             /* packets per second (1 to 1000000) */
int gap = 0;             /* gap/interval between packets in seconds (1 to 86400) */
int linerate = -1;       /* limit packet throughput at the specified Mbps (0 means no limit) */
uint64_t bps = 0;        /* bits per second converted from linerate */
bool default_gap = true; /* true = use captured interval, false = custom interval */
uint64_t max_pkts = 0;   /* send up to the specified number of packets */

/* data */
int trace_files_count = 0;
trace_file_t **trace_files = NULL; /* pointers to trace files */
pcap_t *pd = NULL;                 /* pcap descriptor */
uint8_t pkt_data[ETH_MAX_LEN];     /* packet data including the link-layer header */
struct pcap_sf_pkthdr header;      /* pcap header per packet */
struct token_bucket tb_pps;        /* token bucket for shaping throughput at pps */
struct token_bucket tb_linerate;   /* token bucket for shaping throughput at linerate */

/* stats */
static uint64_t pkts_sent = 0;
static uint64_t bytes_sent = 0;
static uint64_t failed = 0;
struct timeval start = {0, 0};
struct timeval end = {0, 0};

int main(int argc, char **argv)
{
    char *cp;
    int c;
    pcap_if_t *devptr;
    int i;
    int devnum;
    char *device = NULL;
    int loop = 1;
    thiszone = gmt2local(0);

    if ((cp = strrchr(argv[0], '/')) != NULL)
        program_name = cp + 1;
    else
        program_name = argv[0];

    /* process options */
    while ((c = getopt(argc, argv, "dvi:s:l:c:p:t:r:h")) != -1)
    {
        switch (c)
        {
        case 'd':
            if (pcap_findalldevs(&devptr, ebuf) < 0)
                error("%s", ebuf);
            else
            {
                for (i = 0; devptr != 0; i++)
                {
                    (void)printf("%d. %s", i + 1, devptr->name);
                    if (devptr->description != NULL)
                        (void)printf(" (%s)", devptr->description);
                    (void)putchar('\n');
                    devptr = devptr->next;
                }
            }
            exit(EXIT_SUCCESS);
        case 'v':
            ++vflag;
            break;
        case 'i':
            if ((devnum = atoi(optarg)) != 0)
            {
                if (devnum < 0)
                    error("invalid adapter index");
                if (pcap_findalldevs(&devptr, ebuf) < 0)
                    error("%s", ebuf);
                else
                {
                    for (i = 0; i < devnum - 1; i++)
                    {
                        devptr = devptr->next;
                        if (devptr == NULL)
                            error("invalid adapter index");
                    }
                }
                device = devptr->name;
            }
            else
            {
                device = optarg;
            }
            break;
        case 's':
            len = strtol(optarg, NULL, 0);
            if (len != -1 && len != 0)
            {
                if (len < ETH_HDR_LEN || len > ETH_MAX_LEN)
                    error("value for length must be between %d to %d", ETH_HDR_LEN, ETH_MAX_LEN);
            }
            break;
        case 'l':
            loop = strtol(optarg, NULL, 0); /* loop infinitely if loop <= 0 */
            break;
        case 'c':
            max_pkts = strtoul(optarg, NULL, 0); /* send all packets if max_pkts <= 0 */
            break;
        case 'p':
            pps = strtol(optarg, NULL, 0);
            if (pps < 1 || pps > PPS_MAX)
                error("value for pps must be between 1 to %d", PPS_MAX);
            break;
        case 't':
            gap = strtol(optarg, NULL, 0);
            if (gap < 1 || gap > GAP_MAX)
                error("value for gap must be between 1 to %d", GAP_MAX);
            break;
        case 'r':
            linerate = strtol(optarg, NULL, 0);
            if (linerate < LINERATE_MIN || linerate > LINERATE_MAX)
                error("value for rate must be between %d to %d", LINERATE_MIN, LINERATE_MAX);
            if (linerate > 0)
                bps = (uint64_t)linerate * 1000000;
            break;
        case 'h':
        default:
            usage();
        }
    }

    /* don't use captured interval if any of the custom interval options is set */
    if (pps > 0 || gap > 0 || linerate >= 0)
        default_gap = false;

    if (device == NULL)
        error("device not specified");

    if (argv[optind] == NULL)
        error("trace file not specified");

    /* set signal handler for SIGINT (Control-C) */
    (void)signal(SIGINT, cleanup);

    load_trace_files(argc, argv);

    init_pcap(device);

    notice("sending packets through %s", device);

    if (gettimeofday(&start, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));

    clock_gettime(CLOCK_MONOTONIC, &tb_pps.last_add);
    clock_gettime(CLOCK_MONOTONIC, &tb_linerate.last_add);

    /* send infinitely if loop <= 0 until user Control-C */
    while (1)
    {
        for (i = 0; i < trace_files_count; i++) /* for each trace file */
            send_packets(trace_files[i]);

        if (loop > 1)
            loop--;
        else if (loop == 1)
            break;
    }

    cleanup(0);

    /* NOTREACHED */
    exit(EXIT_SUCCESS);
}

void load_trace_files(int argc, char **argv)
{
    struct pcap_file_header preamble; /* pcap file header per trace file */

    trace_files = malloc((argc - optind) * sizeof(trace_file_t *));
    if (trace_files == NULL)
        error("malloc(): cannot allocate memory for trace_files");

    for (int i = optind; i < argc; i++)
    {
        trace_file_t *trace_file = malloc(sizeof(trace_file_t));
        if (trace_file == NULL)
            error("malloc(): cannot allocate memory for trace_file");

        trace_file->filename = argv[i];

        if ((trace_file->fp = fopen(trace_file->filename, "rb")) == NULL)
            error("fopen(): error reading %s", trace_file->filename);

        /*
         * check preamble of each trace file.
         * preamble occupies the first 24 bytes of a trace file
         */
        if (fread(&preamble, PCAP_PREAMBLE_LEN, 1, trace_file->fp) == 0)
            error("fread(): error reading %s", trace_file->filename);

        if (preamble.magic != PCAP_MAGIC && preamble.magic != NSEC_PCAP_MAGIC)
            error("%s is not a valid pcap based trace file", trace_file->filename);

        if (preamble.magic == NSEC_PCAP_MAGIC)
            trace_file->nsec = true;
        else
            trace_file->nsec = false;

        /* load all inter-packet gaps if we are using captured interval */
        if (default_gap)
            load_ipg(trace_file);
        else
            trace_file->ipg = NULL;

        trace_files[trace_files_count++] = trace_file;
    }
}

void load_ipg(trace_file_t *trace_file)
{
    struct timespec curr_ts;  /* timestamp of current packet */
    struct timespec prev_ts;  /* timestamp of previous packet */
    uint64_t pkts = 0;        /* packet index */
    uint64_t i = 0;           /* ipg index */
    uint64_t ipg_cap = 10000; /* initial capacity to store ipg values; doubled as needed */

    trace_file->ipg = malloc(ipg_cap * sizeof(ipg_t));
    if (trace_file->ipg == NULL)
        error("malloc(): cannot allocate memory for ipg");

    /*
     * file pointer has moved past the pcap file header.
     * loop through the remaining data by reading the packet header first.
     * packet header (16 bytes) = timestamp + length
     */
    while (fread(&header, PCAP_HDR_LEN, 1, trace_file->fp) == 1)
    {
        curr_ts.tv_sec = header.ts.tv_sec;
        if (trace_file->nsec)
            curr_ts.tv_nsec = header.ts.tv_usec;
        else
            curr_ts.tv_nsec = header.ts.tv_usec * 1000;

        /* move file pointer to the end of this packet data */
        if (fseek(trace_file->fp, header.caplen, SEEK_CUR) != 0)
            error("fseek(): error reading %s", trace_file->filename);

        if (pkts > 0)
        {
            /* double the capacity to store ipg values if current capacity is hit */
            if (i >= ipg_cap)
            {
                ipg_cap *= 2;
                ipg_t *new_ipg = realloc(trace_file->ipg, ipg_cap * sizeof(ipg_t));
                if (new_ipg == NULL)
                    error("realloc(): cannot allocate memory for new_ipg");
                trace_file->ipg = new_ipg;
            }

            trace_file->ipg[i].ns = (curr_ts.tv_sec - prev_ts.tv_sec) * 1000000000L +
                                    (curr_ts.tv_nsec - prev_ts.tv_nsec);

            /* pps value dictates how next packet is to be throttled during the send */
            if (trace_file->ipg[i].ns == 0)
                trace_file->ipg[i].pps = 0; /* send immediately */
            else if (trace_file->ipg[i].ns <= 1000000000)
                trace_file->ipg[i].pps = 1000000000 / trace_file->ipg[i].ns; /* throttle at pps */
            else
                trace_file->ipg[i].pps = -1; /* pps is less than 1, fallback to sleep for ns */

            ++i;
        }

        ++pkts;

        prev_ts = curr_ts;
    }
}

void init_pcap(char *device)
{
    /* empty error buffer to grab warning message (if exist) from pcap_open_live() below */
    *ebuf = '\0';

    /* note that we are doing this for sending packets, not capture */
    pd = pcap_open_live(device, ETH_MAX_LEN, /* portion of packet to capture */
                        1,                   /* promiscuous mode is on */
                        1000,                /* read timeout, in milliseconds */
                        ebuf);

    if (pd == NULL)
        error("%s", ebuf);
    else if (*ebuf)
        notice("%s", ebuf); /* warning message from pcap_open_live() above */
}

void send_packets(trace_file_t *trace_file)
{
    int pkt_len;       /* packet length to send */
    struct timeval tv; /* current timestamp for verbose output */
    uint64_t pkts = 0; /* packet index */

    /* reset trace file pointer moving past the pcap file header */
    if (fseek(trace_file->fp, PCAP_PREAMBLE_LEN, SEEK_SET) != 0)
        error("fseek(): error reading %s", trace_file->filename);

    /*
     * loop through the remaining data by reading the packet header first.
     * packet header (16 bytes) = timestamp + length
     */
    while (fread(&header, PCAP_HDR_LEN, 1, trace_file->fp) == 1)
    {
        if (len < 0) /* captured length */
            pkt_len = header.caplen;
        else if (len == 0) /* actual length */
            pkt_len = header.len;
        else /* user specified length */
            pkt_len = len;

        /* skip throttling if linerate is set to 0, i.e. send each packet immediately */
        if (linerate != 0)
            throttle(trace_file, pkts, pkt_len * 8);

        load_packet(trace_file, pkt_len, &header);

        if (pcap_sendpacket(pd, pkt_data, pkt_len) == -1)
        {
            notice("%s", pcap_geterr(pd));
            ++failed;
        }
        else
        {
            ++pkts_sent;
            bytes_sent += pkt_len;

            /* verbose output */
            if (vflag)
            {
                if (gettimeofday(&tv, NULL) == -1)
                    notice("gettimeofday(): %s", strerror(errno));
                else
                    ts_print(&tv);

                (void)printf("#%lu (%d bytes)", pkts_sent, pkt_len);

                if (vflag > 1)
                    hex_print(pkt_data, pkt_len);
                else
                    putchar('\n');

                fflush(stdout);
            }
        }

        ++pkts;

        if ((max_pkts > 0) && (pkts_sent >= max_pkts))
            cleanup(0);
    } /* end while */
}

void sleep_ns(uint64_t ns)
{
    /* cumulative drift to adjust ns accordingly based on previous elapsed_ns */
    static int64_t drift_ns = 0;

    struct timespec ts, rem_ts, start_ts, end_ts;
    ts.tv_sec = (ns + drift_ns) / 1000000000;
    ts.tv_nsec = (ns + drift_ns) % 1000000000;

    clock_gettime(CLOCK_MONOTONIC, &start_ts);
    while (nanosleep(&ts, &rem_ts) == -1 && errno == EINTR)
        ts = rem_ts;
    clock_gettime(CLOCK_MONOTONIC, &end_ts);

    uint64_t elapsed_ns =
        (end_ts.tv_sec - start_ts.tv_sec) * 1000000000 + (end_ts.tv_nsec - start_ts.tv_nsec);

    /*
     * if elapsed_ns > ns, the negative drift will shorten the next sleep_ns().
     * if elapsed_ns < ns, the positive drift will lengthen the next sleep_ns()
     */
    drift_ns += ns - elapsed_ns;
}

void throttle(trace_file_t *trace_file, uint64_t pkts, int bits)
{
    /* always send first packet immediately */
    if (pkts_sent == 0)
        return;

    if (pps)
    {
        /* throttle using token bucket algorithm if pps is specified */
        while (!token_bucket_remove(&tb_pps, 1, pps))
            usleep(1);
    }
    else if (bps)
    {
        /* throttle using token bucket algorithm if linerate is specified */
        while (!token_bucket_remove(&tb_linerate, bits, bps))
            usleep(1);
    }
    else if (gap) /* user specified inter-packet gap in seconds */
    {
        sleep_ns(gap * 1000000000L);
    }
    else /* use captured interval */
    {
        /*
         * note that the first packet in this trace file is always sent immediately.
         * this applies even if we are looping the same trace file multiple times
         */
        if (pkts > 0)
        {
            if (trace_file->ipg[pkts - 1].pps == 0) /* send immediately */
                return;
            else if (trace_file->ipg[pkts - 1].pps < 0) /* sleep for ns */
                sleep_ns(trace_file->ipg[pkts - 1].ns);
            else /* throttle using token bucket algorithm at pps */
            {
                while (!token_bucket_remove(&tb_pps, 1, trace_file->ipg[pkts - 1].pps))
                    usleep(1);
            }
        }
    }
}

void load_packet(trace_file_t *trace_file, int pkt_len, struct pcap_sf_pkthdr *header)
{
    int copy_len = pkt_len < header->caplen ? pkt_len : header->caplen;

    if (fread(pkt_data, 1, copy_len, trace_file->fp) != copy_len)
        error("fread(): error reading %s", trace_file->filename);

    /* pad trailing bytes with zeros */
    if (copy_len < pkt_len)
        memset(pkt_data + copy_len, PKT_PAD, pkt_len - copy_len);

    /* move file pointer to the end of this packet data */
    if (copy_len < header->caplen)
    {
        if (fseek(trace_file->fp, header->caplen - copy_len, SEEK_CUR) != 0)
            error("fseek(): error reading %s", trace_file->filename);
    }
}

void info(void)
{
    struct timeval elapsed;
    float seconds;
    unsigned long bits_sent, actual_pps;
    float mbps, gbps;

    if (gettimeofday(&end, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));
    timersub(&end, &start, &elapsed);
    seconds = elapsed.tv_sec + (float)elapsed.tv_usec / 1000000;

    actual_pps = pkts_sent / seconds;
    bits_sent = bytes_sent * 8;
    mbps = bits_sent / seconds / 1000000;
    gbps = bits_sent / seconds / 1000000000;

    (void)putchar('\n');
    notice("sent = %lu packets, %lu bits, %lu bytes", pkts_sent, bits_sent, bytes_sent);
    notice("throughput = %lu pps, %.4f Mbps, %.4f Gbps", actual_pps, mbps, gbps);
    if (failed)
        notice("%lu write attempts failed", failed);
    notice("elapsed time = %f seconds", seconds);
}

void cleanup(int signum)
{
    for (int i = 0; i < trace_files_count; i++)
    {
        fclose(trace_files[i]->fp);
        if (trace_files[i]->ipg != NULL)
            free(trace_files[i]->ipg);
    }
    free(trace_files);
    trace_files = NULL;

    if (signum == -1)
        exit(EXIT_FAILURE);
    else
        info();
    exit(EXIT_SUCCESS);
}

/*
 * Reference: tcpdump's gmt2local.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
int32_t gmt2local(time_t t)
{
    int dt, dir;
    struct tm *gmt, *loc;
    struct tm sgmt;

    if (t == 0)
        t = time(NULL);
    gmt = &sgmt;
    *gmt = *gmtime(&t);
    loc = localtime(&t);
    dt = (loc->tm_hour - gmt->tm_hour) * 60 * 60 + (loc->tm_min - gmt->tm_min) * 60;

    /*
     * If the year or julian day is different, we span 00:00 GMT and must add or subtract a day.
     * Check the year first to avoid problems when the julian day wraps.
     */
    dir = loc->tm_year - gmt->tm_year;
    if (dir == 0)
        dir = loc->tm_yday - gmt->tm_yday;
    dt += dir * 24 * 60 * 60;

    return (dt);
}

/*
 * Reference: tcpdump's print-ascii.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void hex_print(const uint8_t *cp, uint32_t length)
{
    uint32_t i, s;
    uint32_t nshorts;
    uint32_t oset = 0;

    nshorts = length / sizeof(uint16_t);
    i = 0;
    while (nshorts > 0)
    {
        if ((i++ % 8) == 0)
        {
            (void)printf("\n\t0x%04x: ", oset);
            oset += 16;
        }
        s = *cp;
        (void)printf(" %02x%02x", s, *(cp + 1));
        cp += 2;
        nshorts--;
    }
    if (length & 1)
    {
        if ((i % 8) == 0)
            (void)printf("\n\t0x%04x: ", oset);
        (void)printf(" %02x", *cp);
    }
    (void)putchar('\n');
}

/*
 * Reference: tcpdump's util.c
 *
 * Copyright (c) 1990, 1991, 1993, 1994, 1995, 1996, 1997
 *      The Regents of the University of California.  All rights reserved.
 *
 */
void ts_print(const struct timeval *tvp)
{
    int s;

    s = (tvp->tv_sec + thiszone) % 86400;
    (void)printf("%02d:%02d:%02d.%06u ", s / 3600, (s % 3600) / 60, s % 60, (unsigned)tvp->tv_usec);
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
    cleanup(-1);
}

void usage(void)
{
    (void)fprintf(stderr,
                  "%s version %s, Copyright (C) 2006 - 2023 Addy Yeow <ayeowch@gmail.com>\n"
                  "%s\n"
                  "Usage: %s [-d] [-v] [-i interface] [-s length] [-l loop] [-c count]\n"
                  "                [-p pps] [-t gap] [-r rate] [-h] pcap-file(s)\n"
                  "\nOptions:\n"
                  " -d             Print a list of network interfaces available.\n"
                  " -v             Print timestamp for each packet.\n"
                  " -vv            Print timestamp and hex data for each packet.\n"
                  " -i interface   Send 'pcap-file(s)' out onto the network through 'interface'.\n"
                  " -s length      Packet length to send (in bytes). Set 'length' to:\n"
                  "                 0 : Send the actual packet length. This is the default.\n"
                  "                -1 : Send the captured length.\n"
                  "                or any other value from %d to %d.\n"
                  " -l loop        Send 'pcap-file(s)' out onto the network for 'loop' times.\n"
                  "                Set 'loop' to 0 to send 'pcap-file(s)' until stopped.\n"
                  "                To stop, type Control-C.\n"
                  " -c count       Send up to 'count' packets.\n"
                  "                Default is to send all packets from 'pcap-file(s)'.\n"
                  " -p pps         Send 'pps' packets per second.\n"
                  "                Value for 'pps' must be between 1 to %d.\n"
                  " -t gap         Set inter-packet 'gap' in seconds, ignoring the captured\n"
                  "                interval between packets in 'pcap-file(s)'.\n"
                  "                Value for 'gap' must be between 1 to %d.\n"
                  " -r rate        Limit the sending to 'rate' Mbps.\n"
                  "                Value for 'rate' must be between %d to %d.\n"
                  "                This flag is intended to set the desired packet throughput.\n"
                  "                If you want to send packets at line rate of 1000 Mbps,\n"
                  "                try -r 1000. If you want to send packets without rate limit,\n"
                  "                try -r 0. This flag is typically used with -l 0 to send\n"
                  "                'pcap-file(s)' until stopped.\n"
                  " -h             Print version information and usage.\n",
                  program_name, BITTWIST_VERSION, pcap_lib_version(), program_name, ETH_HDR_LEN,
                  ETH_MAX_LEN, PPS_MAX, GAP_MAX, LINERATE_MIN, LINERATE_MAX);
    exit(EXIT_SUCCESS);
}
