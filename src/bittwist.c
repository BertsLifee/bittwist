/*
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * bittwist - pcap based ethernet packet generator
 * Copyright (C) 2006 - 2023 Addy Yeow Chin Heng <ayeowch@gmail.com>
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
int vflag = 0;              /* 1 - print timestamp, 2 - print timestamp and hex data */
int len = 0;                /* packet length to send (-1 = captured, 0 = on wire, or positive
                               value <= 1514) */
int interval = 0;           /* a constant interval in seconds (0 means actual interval
                               will be used instead) */
int linerate = -1;          /* limit packet throughput at the specified Mbps (0 means no limit) */
uint64_t bps = 0;           /* bits per second converted from linerate */
unsigned long max_pkts = 0; /* send up to the specified number of packets */

/* data */
pcap_t *pd = NULL;         /* pcap descriptor */
uint8_t *pkt_data = NULL;  /* packet data including the link-layer header */
FILE **trace_files = NULL; /* pointers to trace files */
int trace_files_count = 0;
struct timespec sleep_ts = {0, 0}; /* sleep duration to shape throughput */
struct timespec curr_ts;           /* timestamp of current packet */
struct timespec prev_ts = {0, 0};  /* timestamp of previous packet */
struct token_bucket tb = {0, 0};   /* token bucket for shaping throughput at linerate */

/* stats */
static unsigned long pkts_sent = 0;
static unsigned long bytes_sent = 0;
static unsigned long failed = 0;
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
    while ((c = getopt(argc, argv, "dvi:s:l:c:p:r:h")) != -1)
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
                if (len < ETHER_HDR_LEN || len > ETHER_MAX_LEN)
                    error("value for length must be between %d to %d", ETHER_HDR_LEN,
                          ETHER_MAX_LEN);
            }
            break;
        case 'l':
            loop = strtol(optarg, NULL, 0); /* loop infinitely if loop <= 0 */
            break;
        case 'c':
            max_pkts = strtoul(optarg, NULL, 0); /* send all packets if max_pkts <= 0 */
            break;
        case 'p':
            interval = strtol(optarg, NULL, 0);
            if (interval < 1 || interval > SLEEP_MAX)
                error("value for sleep must be between 1 to %d", SLEEP_MAX);
            break;
        case 'r':
            linerate = strtol(optarg, NULL, 0);
            if (linerate < LINERATE_MIN || linerate > LINERATE_MAX)
                error("value for rate must be between %d to %d", LINERATE_MIN, LINERATE_MAX);
            bps = (uint64_t)linerate * 1000000;
            tb.last_add = time(NULL);
            break;
        case 'h':
        default:
            usage();
        }
    }

    if (device == NULL)
        error("device not specified");

    if (argv[optind] == NULL)
        error("trace file not specified");

    notice("sending packets through %s", device);

    /* empty error buffer to grab warning message (if exist) from pcap_open_live() below */
    *ebuf = '\0';

    /* note that we are doing this for sending packets, not capture */
    pd = pcap_open_live(device, ETHER_MAX_LEN, /* portion of packet to capture */
                        1,                     /* promiscuous mode is on */
                        1000,                  /* read timeout, in milliseconds */
                        ebuf);

    if (pd == NULL)
        error("%s", ebuf);
    else if (*ebuf)
        notice("%s", ebuf); /* warning message from pcap_open_live() above */

    /* buffer to store data for each packet including its link-layer header, freed in cleanup() */
    pkt_data = (uint8_t *)malloc(sizeof(uint8_t) * ETHER_MAX_LEN);
    if (pkt_data == NULL)
        error("malloc(): cannot allocate memory for pkt_data");
    memset(pkt_data, 0, ETHER_MAX_LEN);

    /* set signal handler for SIGINT (Control-C) */
    (void)signal(SIGINT, cleanup);

    if (gettimeofday(&start, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));

    trace_files = malloc((argc - optind) * sizeof(FILE *));
    for (i = optind; i < argc; i++)
    {
        FILE *fp;
        notice("trace file: %s", argv[i]);
        if ((fp = fopen(argv[i], "rb")) == NULL)
            error("fopen(): error reading %s", argv[i]);
        trace_files[trace_files_count++] = fp;
    }

    /* send infinitely if loop <= 0 until user Control-C */
    while (1)
    {
        for (i = 0; i < trace_files_count; i++) /* for each trace file */
            send_packets(device, trace_files[i], argv[i + optind]);

        if (loop > 1)
            loop--;
        else if (loop == 1)
            break;
    }

    cleanup(0);

    /* NOTREACHED */
    exit(EXIT_SUCCESS);
}

void send_packets(char *device, FILE *fp, char *trace_file)
{
    struct pcap_file_header preamble;
    struct pcap_sf_pkthdr header;
    int pkt_len; /* packet length to send */
    int ret;
    int nsec = 0; /* set to 1 if we have timestamps in nanosecond resolution */
    struct pcap_timeval p_ts;
    struct timeval tv;
    sigset_t block_sig;

    (void)sigemptyset(&block_sig);
    (void)sigaddset(&block_sig, SIGINT);

    /* reset trace file pointer */
    if (fseek(fp, 0, SEEK_SET) != 0)
        error("fseek(): error reading %s", trace_file);

    /* preamble occupies the first 24 bytes of a trace file */
    if (fread(&preamble, sizeof(preamble), 1, fp) == 0)
        error("fread(): error reading %s", trace_file);
    if (preamble.magic != PCAP_MAGIC && preamble.magic != NSEC_PCAP_MAGIC)
        error("%s is not a valid pcap based trace file", trace_file);
    if (preamble.magic == NSEC_PCAP_MAGIC)
        nsec = 1;

    /*
     * loop through the remaining data by reading the packet header first.
     * packet header (16 bytes) = timestamp + length
     */
    while ((ret = fread(&header, sizeof(header), 1, fp)))
    {
        if (ret == 0)
            error("fread(): error reading %s", trace_file);

        /* copy timestamp for current packet */
        memcpy(&p_ts, &header.ts, sizeof(p_ts));
        curr_ts.tv_sec = p_ts.tv_sec;
        if (nsec == 1)
            curr_ts.tv_nsec = p_ts.tv_usec;
        else
            curr_ts.tv_nsec = p_ts.tv_usec * 1000;

        if (len < 0) /* captured length */
            pkt_len = header.caplen;
        else if (len == 0) /* actual length */
            pkt_len = header.len;
        else /* user specified length */
            pkt_len = len;

        throttle(pkt_len);

        load_packet(fp, pkt_len, &header, trace_file);

        (void)sigprocmask(SIG_BLOCK, &block_sig, NULL); /* hold SIGINT */

        /* finish the injection and verbose output before we give way to SIGINT */
        if (pcap_sendpacket(pd, pkt_data, pkt_len) == -1)
        {
            notice("%s", pcap_geterr(pd));
            ++failed;
        }
        else
        {
            ++pkts_sent;
            bytes_sent += pkt_len;

            /* copy timestamp for previous packet sent */
            memcpy(&prev_ts, &curr_ts, sizeof(struct timespec));

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

        (void)sigprocmask(SIG_UNBLOCK, &block_sig, NULL); /* release SIGINT */

        if ((max_pkts > 0) && (pkts_sent >= max_pkts))
            cleanup(0);
    } /* end while */
}

void throttle(int pkt_len)
{
    /*
     * always send first packet immediately.
     * if linerate is set to 0, send each packet immediately
     */
    if (linerate == 0 || !timespecisset(&prev_ts))
        return;

    if (interval > 0) /* user specified interval is in seconds only */
        sleep_ts.tv_sec = interval;
    else /* use captured interval */
    {
        /*
         * fallback to last sleep_ts if curr_ts < prev_ts which can happen when looping over
         * multiple trace file
         */
        if (timespeccmp(&curr_ts, &prev_ts, >=))
            timespecsub(&curr_ts, &prev_ts, &sleep_ts);
    }

    if (bps)
    {
        /* throttle using token bucket algorithm if linerate is specified */
        if (token_bucket_remove(&tb, pkt_len * 8, bps))
            return;
    }
    else if (timespecisset(&sleep_ts))
    {
        if (sleep_ts.tv_sec > SLEEP_MAX)
            notice("warning: next packet has timestamp over %lu seconds away", sleep_ts.tv_sec);
        if (nanosleep(&sleep_ts, NULL) == -1)
            notice("nanosleep(): %s", strerror(errno));
    }
}

void load_packet(FILE *fp, int pkt_len, struct pcap_sf_pkthdr *header, char *trace_file)
{
    int copy_len = pkt_len < header->caplen ? pkt_len : header->caplen;

    if (fread(pkt_data, sizeof(char), copy_len, fp) != copy_len)
        error("fread(): error reading %s", trace_file);

    /* pad trailing bytes with zeros */
    for (int i = copy_len; i < pkt_len; i++)
        pkt_data[i] = PKT_PAD;

    /* move file pointer to the end of this packet data */
    if (copy_len < header->caplen)
    {
        if (fseek(fp, header->caplen - copy_len, SEEK_CUR) != 0)
            error("fseek(): error reading %s", trace_file);
    }
}

void info(void)
{
    struct timeval elapsed;
    float seconds;
    unsigned long bits_sent;
    float mbps, gbps;

    if (gettimeofday(&end, NULL) == -1)
        notice("gettimeofday(): %s", strerror(errno));
    timersub(&end, &start, &elapsed);
    seconds = elapsed.tv_sec + (float)elapsed.tv_usec / 1000000;

    bits_sent = bytes_sent * 8;
    mbps = bits_sent / seconds / 1000000;
    gbps = bits_sent / seconds / 1000000000;

    (void)putchar('\n');
    notice("%lu packets (%lu bytes) sent", pkts_sent, bytes_sent);
    notice("throughput = %.4f Mbps (%.4f Gbps)", mbps, gbps);
    if (failed)
        notice("%lu write attempts failed", failed);
    notice("elapsed time = %f seconds", seconds);
}

void cleanup(int signum)
{
    free(pkt_data);
    pkt_data = NULL;

    for (int i = 0; i < trace_files_count; i++)
        fclose(trace_files[i]);
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
                  "%s version %s\n"
                  "%s\n"
                  "Usage: %s [-d] [-v] [-i interface] [-s length] [-l loop] [-c count]\n"
                  "                [-p sleep] [-r rate] [-h] pcap-file(s)\n"
                  "\nOptions:\n"
                  " -d             Print a list of network interfaces available.\n"
                  " -v             Print timestamp for each packet.\n"
                  " -vv            Print timestamp and hex data for each packet.\n"
                  " -i interface   Send 'pcap-file(s)' out onto the network through 'interface'.\n"
                  " -s length      Packet length to send (in bytes). Set 'length' to:\n"
                  "                     0 to send the actual packet length. This is the default.\n"
                  "                    -1 to send the captured length.\n"
                  "                or any other value from %d to %d.\n"
                  " -l loop        Send 'pcap-file(s)' out onto the network for 'loop' times.\n"
                  "                Set 'loop' to 0 to send 'pcap-file(s)' until stopped.\n"
                  "                To stop, type Control-C.\n"
                  " -c count       Send up to 'count' packets.\n"
                  "                Default is to send all packets from 'pcap-file(s)'.\n"
                  " -p sleep       Set interval to 'sleep' (in seconds), ignoring the actual\n"
                  "                interval.\n"
                  "                Value for 'sleep' must be between 1 to %d.\n"
                  " -r rate        Limit the sending to 'rate' Mbps.\n"
                  "                Value for 'rate' must be between %d to %d.\n"
                  "                This flag is intended to set the desired packet throughput.\n"
                  "                If you want to send packets at line rate of 1000 Mbps,\n"
                  "                try -r 1000. If you want to send packets without rate limit,\n"
                  "                try -r 0. This flag is typically used with -l 0 to send\n"
                  "                'pcap-file(s)' until stopped.\n"
                  " -h             Print version information and usage.\n",
                  program_name, BITTWIST_VERSION, pcap_lib_version(), program_name, ETHER_HDR_LEN,
                  ETHER_MAX_LEN, SLEEP_MAX, LINERATE_MIN, LINERATE_MAX);
    exit(EXIT_SUCCESS);
}
