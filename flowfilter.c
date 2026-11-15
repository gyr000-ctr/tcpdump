/*
 * Copyright (c) 2026 The Tcpdump Group
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 *
 * Stateful flow-based filtering for tcpdump.  See flowfilter.h for the
 * overview.  Everything in this file is fail-open: any internal
 * problem makes flow_filter_packet() pass the packet (as the stateless
 * BPF filter would) and increments the fallback counter, rather than
 * silently dropping traffic.
 */

#include <config.h>

#include "netdissect-stdinc.h"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <pcap.h>

#ifdef HAVE_REGEX_H
#include <regex.h>
#endif

#ifdef HAVE_PTHREAD_H
#include <pthread.h>
#endif

#ifdef _WIN32
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#endif

#include "flowfilter.h"

/* Default bounds, used when the caller leaves a field zero. */
#define FF_DEFAULT_MAX_FLOWS	65536U
#define FF_DEFAULT_TIMEOUT_SEC	300U
#define FF_DEFAULT_BUFMAX	16384U	/* per-flow payload scan buffer */
#define FF_DEFAULT_PREBUF	65536U	/* per-flow pre-match packet buffer */
#define FF_DEFAULT_MAX_MEM	(64U * 1024U * 1024U)

#define FF_FRAG_MAP_SIZE	4096U	/* hard bound on fragment map entries */
#define FF_SWEEP_PER_PACKET	8U	/* amortized timeout sweep work */

#define IP_PROTO_TCP	6
#define IP_PROTO_UDP	17
#define IP_PROTO_SCTP	132

#define IPV6_NEXTHDR_HOP	0
#define IPV6_NEXTHDR_TCP	6
#define IPV6_NEXTHDR_UDP	17
#define IPV6_NEXTHDR_ROUTE	43
#define IPV6_NEXTHDR_FRAG	44
#define IPV6_NEXTHDR_AH		51
#define IPV6_NEXTHDR_DEST	60
#define IPV6_NEXTHDR_SCTP	132

/*
 * Concurrency: tcpdump's capture callback is single-threaded today,
 * but the filter is safe to call from multiple capture threads; all
 * public entry points serialize on this mutex when pthreads are
 * available.  lock_waits counts acquisitions as a concurrency metric.
 */
#ifdef HAVE_PTHREAD_H
static pthread_mutex_t ff_mutex = PTHREAD_MUTEX_INITIALIZER;
#define FF_LOCK()   do { pthread_mutex_lock(&ff_mutex); } while (0)
#define FF_UNLOCK() do { pthread_mutex_unlock(&ff_mutex); } while (0)
#else
#define FF_LOCK()   do { } while (0)
#define FF_UNLOCK() do { } while (0)
#endif

/* Canonical 5-tuple: endpoint 0 <= endpoint 1 (address, then port). */
struct flow_key {
	uint8_t		ipver;	/* 4 or 6 */
	uint8_t		proto;
	uint16_t	port[2];
	uint8_t		addr[2][16];
};

/* A packet buffered while waiting for a payload regex match. */
struct pktbuf {
	struct pktbuf		*next;
	struct pcap_pkthdr	h;
	uint64_t		pktno;
	uint32_t		len;	/* bytes in data[] */
	u_char			data[1];
};

struct flow_entry {
	struct flow_key		key;
	int			initiator;	/* 0 or 1: endpoint that
						   sent the first packet */
	uint64_t		first_ms;
	uint64_t		last_ms;
	uint64_t		pkts[2];	/* per-direction packets;
						   index 0 = ep0 -> ep1 */
#define FF_MATCH_NONE	0
#define FF_MATCH_YES	1	/* regex matched */
#define FF_MATCH_FAILOPEN 2	/* fail-open: pass everything */
	int			matched;
	u_char			*scanbuf[2];	/* payload scan buffers */
	uint32_t		scanlen[2];
	uint32_t		scancap[2];
	struct pktbuf		*pre_head;
	struct pktbuf		*pre_tail;
	uint32_t		pre_bytes;
	struct flow_entry	*hnext;
	struct flow_entry	*lru_prev;
	struct flow_entry	*lru_next;
};

/* Map from (addresses, protocol, IP fragment ID) to a flow key. */
struct frag_entry {
	struct frag_entry	*hnext;
	uint8_t			ipver;
	uint8_t			proto;
	uint8_t			src[16];
	uint8_t			dst[16];
	uint32_t		id;
	struct flow_key		flow;
	uint64_t		last_ms;
};

static struct flowfilter_config ff_cfg;
static int ff_inited;
static int ff_dlt;
static struct flowfilter_stats ff_stats;
static char ff_errstr[256];

static struct flow_entry **ff_buckets;	/* hash table */
static uint32_t ff_nbuckets;		/* power of two */
static struct flow_entry *ff_lru_head;	/* most recently used */
static struct flow_entry *ff_lru_tail;	/* least recently used */

static struct frag_entry **ff_frag_buckets;
static uint32_t ff_frag_nbuckets;
static uint32_t ff_frag_count;

static flowfilter_emit_cb ff_emit_cb;
static void *ff_emit_ctx;

#if defined(HAVE_REGEX_H) && defined(HAVE_REGCOMP)
static regex_t ff_re;
static int ff_re_compiled;
#define FF_HAVE_REGEX 1
#endif

static uint64_t
ff_now_ms(const struct pcap_pkthdr *h)
{
	return (uint64_t)h->ts.tv_sec * 1000ULL +
	    (uint64_t)h->ts.tv_usec / 1000ULL;
}

static void
ff_audit(const char *fmt, ...)
{
	va_list ap;

	if (!ff_cfg.audit)
		return;
	fprintf(stderr, "flowfilter: ");
	va_start(ap, fmt);
	vfprintf(stderr, fmt, ap);
	va_end(ap);
	putc('\n', stderr);
}

static void
ff_audit_key(const char *event, const struct flow_key *k)
{
	char src[INET6_ADDRSTRLEN], dst[INET6_ADDRSTRLEN];
	int af;

	if (!ff_cfg.audit)
		return;
	af = (k->ipver == 6) ? AF_INET6 : AF_INET;
	if (inet_ntop(af, k->addr[0], src, sizeof(src)) == NULL)
		snprintf(src, sizeof(src), "?");
	if (inet_ntop(af, k->addr[1], dst, sizeof(dst)) == NULL)
		snprintf(dst, sizeof(dst), "?");
	ff_audit("%s %s %s:%u <-> %s:%u", event,
	    k->ipver == 6 ? "ipv6" : "ipv4", src, k->port[0],
	    dst, k->port[1]);
}

/*
 * Memory accounting.  All dynamic buffer memory (payload scan buffers
 * and pre-match packet buffers) is charged against ff_cfg.max_mem;
 * the flow table itself is bounded by ff_cfg.max_flows entries.
 */
static int
ff_mem_charge(uint64_t bytes)
{
	if (ff_stats.mem_current + bytes > ff_cfg.max_mem) {
		ff_stats.mem_cap_events++;
		return -1;
	}
	ff_stats.mem_current += bytes;
	if (ff_stats.mem_current > ff_stats.mem_peak)
		ff_stats.mem_peak = ff_stats.mem_current;
	return 0;
}

static void
ff_mem_uncharge(uint64_t bytes)
{
	if (bytes > ff_stats.mem_current)
		ff_stats.mem_current = 0;
	else
		ff_stats.mem_current -= bytes;
}

/* ------------------------------------------------------------------ */
/* Packet parsing.                                                    */
/* ------------------------------------------------------------------ */

struct pkt_tuple {
	int		valid;		/* a 5-tuple was extracted */
	uint8_t		ipver;
	uint8_t		proto;
	uint8_t		src[16];
	uint8_t		dst[16];
	uint16_t	sport;
	uint16_t	dport;
	int		frag_nonfirst;	/* non-initial fragment, no L4 */
	int		frag_more;	/* MF set / more fragments */
	uint32_t	frag_id;
	const u_char	*payload;
	uint32_t	payload_len;
};

static uint16_t
get_be16(const u_char *p)
{
	return (uint16_t)((p[0] << 8) | p[1]);
}

static uint32_t
get_be32(const u_char *p)
{
	return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) |
	    ((uint32_t)p[2] << 8) | (uint32_t)p[3];
}

static void
parse_l4(struct pkt_tuple *t, const u_char *p, uint32_t avail)
{
	uint32_t hdrlen;

	t->sport = 0;
	t->dport = 0;
	t->payload = NULL;
	t->payload_len = 0;
	switch (t->proto) {
	case IP_PROTO_TCP:
		if (avail < 20)
			return;
		t->sport = get_be16(p);
		t->dport = get_be16(p + 2);
		hdrlen = (uint32_t)((p[12] >> 4) & 0xf) * 4;
		if (hdrlen < 20 || hdrlen > avail)
			return;
		t->payload = p + hdrlen;
		t->payload_len = avail - hdrlen;
		break;
	case IP_PROTO_UDP:
		if (avail < 8)
			return;
		t->sport = get_be16(p);
		t->dport = get_be16(p + 2);
		t->payload = p + 8;
		t->payload_len = avail - 8;
		break;
	case IP_PROTO_SCTP:
		if (avail < 12)
			return;
		t->sport = get_be16(p);
		t->dport = get_be16(p + 2);
		t->payload = p + 12;
		t->payload_len = avail - 12;
		break;
	default:
		/* No ports; the flow is keyed on addresses+protocol. */
		t->payload = p;
		t->payload_len = avail;
		break;
	}
}

static void
parse_ipv4(struct pkt_tuple *t, const u_char *p, uint32_t avail)
{
	uint32_t ihl, total_len, l4avail;
	uint16_t frag;

	if (avail < 20 || (p[0] >> 4) != 4)
		return;
	ihl = (uint32_t)(p[0] & 0x0f) * 4;
	if (ihl < 20 || ihl > avail)
		return;
	total_len = get_be16(p + 2);
	if (total_len < ihl || total_len > avail)
		total_len = avail;	/* truncated capture: use what we have */
	t->ipver = 4;
	t->proto = p[9];
	memset(t->src, 0, sizeof(t->src));
	memset(t->dst, 0, sizeof(t->dst));
	memcpy(t->src, p + 12, 4);
	memcpy(t->dst, p + 16, 4);
	frag = get_be16(p + 6);
	t->frag_more = (frag & 0x2000) != 0;
	t->frag_id = get_be16(p + 4);
	if ((frag & 0x1fff) != 0) {
		/*
		 * Non-initial fragment: no transport header here.  The
		 * payload still feeds the flow's scan buffer if the
		 * fragment map resolves the flow.
		 */
		t->frag_nonfirst = 1;
		t->payload = p + ihl;
		t->payload_len = total_len - ihl;
		t->valid = 1;
		return;
	}
	l4avail = total_len - ihl;
	parse_l4(t, p + ihl, l4avail);
	t->valid = 1;
}

static void
parse_ipv6(struct pkt_tuple *t, const u_char *p, uint32_t avail)
{
	uint32_t plen, off, hdrlen, nxt, i;
	uint16_t fragword;

	if (avail < 40 || (p[0] >> 4) != 6)
		return;
	plen = get_be16(p + 4);
	if ((uint64_t)40 + plen > avail)
		plen = avail - 40;	/* truncated capture */
	t->ipver = 6;
	t->proto = p[6];
	memcpy(t->src, p + 8, 16);
	memcpy(t->dst, p + 24, 16);
	off = 40;
	nxt = t->proto;
	/* Walk a bounded number of extension headers. */
	for (i = 0; i < 8; i++) {
		if (nxt == IPV6_NEXTHDR_TCP || nxt == IPV6_NEXTHDR_UDP ||
		    nxt == IPV6_NEXTHDR_SCTP)
			break;
		if (nxt == IPV6_NEXTHDR_HOP || nxt == IPV6_NEXTHDR_ROUTE ||
		    nxt == IPV6_NEXTHDR_DEST) {
			if (off + 2 > 40 + plen)
				return;
			hdrlen = ((uint32_t)p[off + 1] + 1) * 8;
			nxt = p[off];
			off += hdrlen;
			continue;
		}
		if (nxt == IPV6_NEXTHDR_AH) {
			if (off + 2 > 40 + plen)
				return;
			hdrlen = ((uint32_t)p[off + 1] + 2) * 4;
			nxt = p[off];
			off += hdrlen;
			continue;
		}
		if (nxt == IPV6_NEXTHDR_FRAG) {
			if (off + 8 > 40 + plen)
				return;
			fragword = get_be16(p + off + 2);
			t->frag_more = (fragword & 0x1) != 0;
			t->frag_id = get_be32(p + off + 4);
			nxt = p[off];
			off += 8;
			if ((fragword & 0xfff8) != 0) {
				/* Non-initial fragment. */
				t->frag_nonfirst = 1;
				t->proto = nxt;
				if (off < 40 + plen) {
					t->payload = p + off;
					t->payload_len = 40 + plen - off;
				}
				t->valid = 1;
				return;
			}
			continue;
		}
		/* Unknown or final next-header: stop walking. */
		break;
	}
	if (off > 40 + plen)
		return;
	t->proto = nxt;
	parse_l4(t, p + off, 40 + plen - off);
	t->valid = 1;
}

/*
 * Extract a 5-tuple from a packet.  Returns 0 on success, -1 if the
 * packet cannot be classified (caller fails open).
 */
static int
parse_packet(int dlt, const struct pcap_pkthdr *h, const u_char *sp,
    struct pkt_tuple *t)
{
	uint32_t caplen = h->caplen;
	uint32_t off = 0;
	uint16_t ethertype = 0;
	int i;

	memset(t, 0, sizeof(*t));

	switch (dlt) {
	case DLT_EN10MB:
		if (caplen < 14)
			return -1;
		ethertype = get_be16(sp + 12);
		off = 14;
		/* Up to two VLAN tags. */
		for (i = 0; i < 2; i++) {
			if (ethertype != 0x8100 && ethertype != 0x88a8 &&
			    ethertype != 0x9100)
				break;
			if (caplen < off + 4)
				return -1;
			ethertype = get_be16(sp + off + 2);
			off += 4;
		}
		break;
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
		if (caplen < 16)
			return -1;
		ethertype = get_be16(sp + 14);
		off = 16;
		break;
#endif
#ifdef DLT_LINUX_SLL2
	case DLT_LINUX_SLL2:
		if (caplen < 20)
			return -1;
		ethertype = get_be16(sp);
		off = 20;
		break;
#endif
	case DLT_RAW:
		off = 0;
		if (caplen < 1)
			return -1;
		ethertype = ((sp[0] >> 4) == 6) ? 0x86dd : 0x0800;
		break;
#ifdef DLT_NULL
	case DLT_NULL:
#endif
#if defined(DLT_LOOP) && !defined(DLT_NULL)
	case DLT_LOOP:
#endif
	{
		uint32_t fam;
		if (caplen < 4)
			return -1;
		/* The 4-byte family is in the capturing host's byte order;
		 * try both interpretations. */
		fam = get_be32(sp);
		if (fam == 2)
			ethertype = 0x0800;
		else if (fam == 10 || fam == 24 || fam == 28 || fam == 30)
			ethertype = 0x86dd;
		else if ((fam & 0xffff) == 0 || (fam >> 16) == 0) {
			/* plausibly little-endian on a big-endian reader or
			 * vice versa; fall through to the nibble test */
			if ((sp[4] >> 4) == 4)
				ethertype = 0x0800;
			else if ((sp[4] >> 4) == 6)
				ethertype = 0x86dd;
			else
				return -1;
		} else
			return -1;
		off = 4;
		break;
	}
	default:
		return -1;
	}

	if (ethertype == 0x0800)
		parse_ipv4(t, sp + off, caplen - off);
	else if (ethertype == 0x86dd)
		parse_ipv6(t, sp + off, caplen - off);
	else
		return -1;
	return t->valid ? 0 : -1;
}

/* ------------------------------------------------------------------ */
/* Flow table.                                                        */
/* ------------------------------------------------------------------ */

static int
endpoint_cmp(const uint8_t *a1, uint16_t p1, const uint8_t *a2, uint16_t p2)
{
	int c = memcmp(a1, a2, 16);

	if (c != 0)
		return c;
	if (p1 < p2)
		return -1;
	if (p1 > p2)
		return 1;
	return 0;
}

static void
make_flow_key(struct flow_key *k, const struct pkt_tuple *t)
{
	memset(k, 0, sizeof(*k));
	k->ipver = t->ipver;
	k->proto = t->proto;
	if (endpoint_cmp(t->src, t->sport, t->dst, t->dport) <= 0) {
		memcpy(k->addr[0], t->src, 16);
		memcpy(k->addr[1], t->dst, 16);
		k->port[0] = t->sport;
		k->port[1] = t->dport;
	} else {
		memcpy(k->addr[0], t->dst, 16);
		memcpy(k->addr[1], t->src, 16);
		k->port[0] = t->dport;
		k->port[1] = t->sport;
	}
}

static uint64_t
hash_flow_key(const struct flow_key *k)
{
	uint64_t h = 1469598103934665603ULL;
	const u_char *p = (const u_char *)k;
	size_t i;

	/* The key is fully memset, so hashing raw bytes is safe. */
	for (i = 0; i < sizeof(*k); i++) {
		h ^= p[i];
		h *= 1099511628211ULL;
	}
	return h;
}

static int
flow_key_equal(const struct flow_key *a, const struct flow_key *b)
{
	return memcmp(a, b, sizeof(*a)) == 0;
}

static void
lru_remove(struct flow_entry *e)
{
	if (e->lru_prev != NULL)
		e->lru_prev->lru_next = e->lru_next;
	else
		ff_lru_head = e->lru_next;
	if (e->lru_next != NULL)
		e->lru_next->lru_prev = e->lru_prev;
	else
		ff_lru_tail = e->lru_prev;
	e->lru_prev = e->lru_next = NULL;
}

static void
lru_touch(struct flow_entry *e)
{
	if (e == ff_lru_head)
		return;
	/* Remove only if the entry is currently linked into the list. */
	if (e->lru_prev != NULL || e->lru_next != NULL || ff_lru_tail == e)
		lru_remove(e);
	e->lru_next = ff_lru_head;
	if (ff_lru_head != NULL)
		ff_lru_head->lru_prev = e;
	ff_lru_head = e;
	if (ff_lru_tail == NULL)
		ff_lru_tail = e;
}

static struct flow_entry *
flow_lookup(const struct flow_key *k)
{
	struct flow_entry *e;

	for (e = ff_buckets[hash_flow_key(k) & (ff_nbuckets - 1)];
	    e != NULL; e = e->hnext) {
		if (flow_key_equal(&e->key, k))
			return e;
	}
	return NULL;
}

static void
flow_free_buffers(struct flow_entry *e)
{
	struct pktbuf *pb;
	int i;

	for (i = 0; i < 2; i++) {
		if (e->scanbuf[i] != NULL) {
			ff_mem_uncharge(e->scancap[i]);
			free(e->scanbuf[i]);
			e->scanbuf[i] = NULL;
			e->scanlen[i] = e->scancap[i] = 0;
		}
	}
	while ((pb = e->pre_head) != NULL) {
		e->pre_head = pb->next;
		ff_mem_uncharge(sizeof(struct pktbuf) - 1 + pb->len);
		free(pb);
	}
	e->pre_tail = NULL;
	e->pre_bytes = 0;
}

static void
flow_remove(struct flow_entry *e)
{
	uint64_t h = hash_flow_key(&e->key) & (ff_nbuckets - 1);
	struct flow_entry **pp = &ff_buckets[h];

	while (*pp != NULL) {
		if (*pp == e) {
			*pp = e->hnext;
			break;
		}
		pp = &(*pp)->hnext;
	}
	lru_remove(e);
	flow_free_buffers(e);
	free(e);
	ff_stats.flows_active--;
}

/* Expire idle flows, at most maxn of them, from the LRU tail. */
static void
flow_sweep_timeouts(uint64_t now_ms, unsigned int maxn)
{
	uint64_t timeout_ms = (uint64_t)ff_cfg.timeout_sec * 1000ULL;

	while (maxn-- > 0 && ff_lru_tail != NULL) {
		struct flow_entry *e = ff_lru_tail;

		if (now_ms - e->last_ms <= timeout_ms)
			break;
		ff_stats.timeouts++;
		ff_audit_key("timeout", &e->key);
		flow_remove(e);
	}
}

static struct flow_entry *
flow_create(const struct flow_key *k, uint64_t now_ms)
{
	struct flow_entry *e;
	uint64_t h;

	/* Make room: first expire idle flows, then evict LRU. */
	if (ff_stats.flows_active >= ff_cfg.max_flows) {
		ff_stats.table_full++;
		ff_audit("table full (%llu active), evicting LRU",
		    (unsigned long long)ff_stats.flows_active);
		flow_sweep_timeouts(now_ms, ff_cfg.max_flows);
		while (ff_stats.flows_active >= ff_cfg.max_flows &&
		    ff_lru_tail != NULL) {
			struct flow_entry *victim = ff_lru_tail;

			ff_stats.evictions++;
			ff_audit_key("evict", &victim->key);
			flow_remove(victim);
		}
		if (ff_stats.flows_active >= ff_cfg.max_flows)
			return NULL;	/* cannot happen, but fail open */
	}
	e = (struct flow_entry *)calloc(1, sizeof(*e));
	if (e == NULL)
		return NULL;
	e->key = *k;
	e->initiator = -1;
	e->first_ms = e->last_ms = now_ms;
	h = hash_flow_key(&e->key) & (ff_nbuckets - 1);
	e->hnext = ff_buckets[h];
	ff_buckets[h] = e;
	lru_touch(e);
	ff_stats.flows_created++;
	ff_stats.flows_active++;
	ff_audit_key("create", &e->key);
	return e;
}

/* ------------------------------------------------------------------ */
/* Fragment map.                                                      */
/* ------------------------------------------------------------------ */

static uint64_t
hash_frag(uint8_t ipver, uint8_t proto, uint32_t id,
    const uint8_t *src, const uint8_t *dst)
{
	uint64_t h = 1469598103934665603ULL;
	size_t i;

	h ^= ipver; h *= 1099511628211ULL;
	h ^= proto; h *= 1099511628211ULL;
	h ^= id;    h *= 1099511628211ULL;
	for (i = 0; i < 16; i++) {
		h ^= src[i]; h *= 1099511628211ULL;
		h ^= dst[i]; h *= 1099511628211ULL;
	}
	return h;
}

static struct frag_entry *
frag_lookup(const struct pkt_tuple *t)
{
	uint64_t h = hash_frag(t->ipver, t->proto, t->frag_id,
	    t->src, t->dst) & (ff_frag_nbuckets - 1);
	struct frag_entry *fe;

	for (fe = ff_frag_buckets[h]; fe != NULL; fe = fe->hnext) {
		if (fe->ipver == t->ipver && fe->proto == t->proto &&
		    fe->id == t->frag_id &&
		    memcmp(fe->src, t->src, 16) == 0 &&
		    memcmp(fe->dst, t->dst, 16) == 0)
			return fe;
	}
	return NULL;
}

static void
frag_insert(const struct pkt_tuple *t, const struct flow_key *k,
    uint64_t now_ms)
{
	uint64_t h;
	struct frag_entry *fe;

	if (ff_frag_count >= FF_FRAG_MAP_SIZE) {
		/* Evict the stalest entry (clock sweep over one bucket). */
		uint64_t oldest = UINT64_MAX;
		struct frag_entry **victim = NULL, **pp;
		uint32_t i;

		for (i = 0; i < ff_frag_nbuckets; i++) {
			for (pp = &ff_frag_buckets[i]; *pp != NULL;
			    pp = &(*pp)->hnext) {
				if ((*pp)->last_ms < oldest) {
					oldest = (*pp)->last_ms;
					victim = pp;
				}
			}
		}
		if (victim != NULL) {
			struct frag_entry *old = *victim;
			*victim = old->hnext;
			free(old);
			ff_frag_count--;
		}
	}
	fe = (struct frag_entry *)calloc(1, sizeof(*fe));
	if (fe == NULL)
		return;
	fe->ipver = t->ipver;
	fe->proto = t->proto;
	memcpy(fe->src, t->src, 16);
	memcpy(fe->dst, t->dst, 16);
	fe->id = t->frag_id;
	fe->flow = *k;
	fe->last_ms = now_ms;
	h = hash_frag(t->ipver, t->proto, t->frag_id, t->src, t->dst) &
	    (ff_frag_nbuckets - 1);
	fe->hnext = ff_frag_buckets[h];
	ff_frag_buckets[h] = fe;
	ff_frag_count++;
}

/* ------------------------------------------------------------------ */
/* Regex payload scanning and pre-match buffering.                    */
/* ------------------------------------------------------------------ */

/* Direction filter test: does a packet traveling in direction dir
 * (0 = ep0->ep1, 1 = ep1->ep0) pass the configured direction? */
static int
dir_passes(const struct flow_entry *e, int dir)
{
	switch (ff_cfg.dir) {
	case FLOW_DIR_FWD:
		return dir == e->initiator;
	case FLOW_DIR_REV:
		return dir != e->initiator;
	default:
		return 1;
	}
}

/*
 * Flush the pre-match buffer of a flow through the emit callback and
 * release it.  If emit_all is false, only packets passing the
 * direction filter are emitted (regex-match flush); if it is true,
 * every buffered packet is emitted (fail-open flush, reverting to
 * stateless behavior).
 */
static void
flow_flush_prebuf(struct flow_entry *e, int emit_all)
{
	struct pktbuf *pb;
	int dir;

	while ((pb = e->pre_head) != NULL) {
		e->pre_head = pb->next;
		dir = (int)(pb->pktno >> 63);
		if ((emit_all || dir_passes(e, dir)) && ff_emit_cb != NULL)
			ff_emit_cb(ff_emit_ctx, &pb->h, pb->data,
			    pb->pktno & 0x7fffffffffffffffULL);
		ff_mem_uncharge(sizeof(struct pktbuf) - 1 + pb->len);
		free(pb);
	}
	e->pre_tail = NULL;
	e->pre_bytes = 0;
}

/* Buffer a packet that arrived before the flow matched. */
static void
flow_buffer_packet(struct flow_entry *e, const struct pcap_pkthdr *h,
    const u_char *sp, uint64_t pktno, int dir)
{
	struct pktbuf *pb;
	uint64_t need;

	if (e->pre_bytes + h->caplen > ff_cfg.prebuf_max) {
		/*
		 * Per-flow bound reached: keep the beginning of the
		 * session, drop this packet from the buffer.  The
		 * filter still works; the session capture is just
		 * truncated at the head.
		 */
		ff_stats.prebuf_dropped++;
		return;
	}
	need = sizeof(struct pktbuf) - 1 + h->caplen;
	if (ff_mem_charge(need) != 0) {
		/* Global memory cap: fail open for this flow. */
		ff_stats.fallbacks++;
		ff_audit("memory cap hit, failing open");
		e->matched = FF_MATCH_FAILOPEN;
		flow_flush_prebuf(e, 1);
		return;
	}
	pb = (struct pktbuf *)malloc(need);
	if (pb == NULL) {
		ff_mem_uncharge(need);
		ff_stats.fallbacks++;
		e->matched = FF_MATCH_FAILOPEN;
		flow_flush_prebuf(e, 1);
		return;
	}
	pb->next = NULL;
	pb->h = *h;
	/* Encode the direction in the top bit of pktno; capture numbers
	 * nowhere near 2^63 are realistic. */
	pb->pktno = pktno | ((uint64_t)(dir != 0) << 63);
	pb->len = h->caplen;
	memcpy(pb->data, sp, h->caplen);
	if (e->pre_tail != NULL)
		e->pre_tail->next = pb;
	else
		e->pre_head = pb;
	e->pre_tail = pb;
	e->pre_bytes += h->caplen;
}

/*
 * Append payload to the per-direction scan buffer and test the regex.
 * Returns 1 if the flow now matches, 0 if not, -1 on resource
 * exhaustion (caller fails open).
 */
static int
flow_scan_payload(struct flow_entry *e, int dir, const u_char *payload,
    uint32_t payload_len)
{
#ifdef FF_HAVE_REGEX
	uint32_t need, newcap;
	u_char *nb;
	int rc;

	if (payload_len == 0 || e->scanlen[dir] >= ff_cfg.flow_bufmax)
		return 0;
	if (payload_len > ff_cfg.flow_bufmax - e->scanlen[dir])
		payload_len = ff_cfg.flow_bufmax - e->scanlen[dir];
	need = e->scanlen[dir] + payload_len;
	if (need > e->scancap[dir]) {
		newcap = e->scancap[dir] ? e->scancap[dir] : 256;
		while (newcap < need)
			newcap *= 2;
		if (ff_mem_charge(newcap - e->scancap[dir]) != 0)
			return -1;
		nb = (u_char *)realloc(e->scanbuf[dir], newcap + 1);
		if (nb == NULL) {
			ff_mem_uncharge(newcap - e->scancap[dir]);
			return -1;
		}
		e->scanbuf[dir] = nb;
		e->scancap[dir] = newcap;
	}
	memcpy(e->scanbuf[dir] + e->scanlen[dir], payload, payload_len);
	e->scanlen[dir] += payload_len;
	e->scanbuf[dir][e->scanlen[dir]] = '\0';

#ifdef REG_STARTEND
	{
		regmatch_t m;

		m.rm_so = 0;
		m.rm_eo = (regoff_t)e->scanlen[dir];
		rc = regexec(&ff_re, (const char *)e->scanbuf[dir], 1, &m,
		    REG_STARTEND);
	}
#else
	rc = regexec(&ff_re, (const char *)e->scanbuf[dir], 0, NULL, 0);
#endif
	return (rc == 0) ? 1 : 0;
#else
	(void)e; (void)dir; (void)payload; (void)payload_len;
	return 0;
#endif
}

/* ------------------------------------------------------------------ */
/* Per-packet filter logic.                                           */
/* ------------------------------------------------------------------ */

/*
 * Apply the configured mode to a packet attributed to a flow.
 * Returns 1 to pass the packet, 0 to suppress it.
 */
static int
flow_apply(struct flow_entry *e, const struct pcap_pkthdr *h,
    const u_char *sp, uint64_t pktno, int dir,
    const u_char *payload, uint32_t payload_len)
{
	int dirpass = dir_passes(e, dir);

	if (ff_cfg.pattern != NULL) {
		/* Regex mode. */
		int m;

		if (e->matched == FF_MATCH_FAILOPEN)
			return 1;
		if (e->matched == FF_MATCH_YES)
			return dirpass;
		/*
		 * Not matched yet: scan this packet's payload first; if
		 * the flow matches, flush the buffered pre-match packets
		 * and let the caller emit this packet normally.  If not,
		 * buffer this packet and suppress it for now.
		 */
		m = flow_scan_payload(e, dir, payload, payload_len);
		if (m < 0) {
			/* Resource exhaustion: fail open. */
			ff_stats.fallbacks++;
			ff_audit("scan buffer failure, failing open");
			e->matched = FF_MATCH_FAILOPEN;
			flow_flush_prebuf(e, 1);
			return 1;
		}
		if (m == 1) {
			e->matched = FF_MATCH_YES;
			ff_stats.regex_matches++;
			ff_audit_key("regex match", &e->key);
			flow_flush_prebuf(e, 0);
			/* Free the scan buffers; no longer needed. */
			if (e->scanbuf[0] != NULL) {
				ff_mem_uncharge(e->scancap[0]);
				free(e->scanbuf[0]);
				e->scanbuf[0] = NULL;
				e->scancap[0] = e->scanlen[0] = 0;
			}
			if (e->scanbuf[1] != NULL) {
				ff_mem_uncharge(e->scancap[1]);
				free(e->scanbuf[1]);
				e->scanbuf[1] = NULL;
				e->scancap[1] = e->scanlen[1] = 0;
			}
			return dirpass;
		}
		flow_buffer_packet(e, h, sp, pktno, dir);
		if (e->matched == FF_MATCH_FAILOPEN)
			return 1;	/* buffer failure: failed open */
		return 0;	/* buffered, not yet matched */
	}

	if (ff_cfg.first_n > 0) {
		/* First-N mode: count packets in the selected direction
		 * class (both directions, or the chosen one). */
		uint64_t n;

		if (ff_cfg.dir == FLOW_DIR_BOTH)
			n = e->pkts[0] + e->pkts[1];
		else
			n = e->pkts[dir];
		return dirpass && n <= ff_cfg.first_n;
	}

	/* Direction-only mode. */
	return dirpass;
}

static int
flow_filter_packet_locked(const struct pcap_pkthdr *h, const u_char *sp,
    uint64_t pktno)
{
	struct pkt_tuple t;
	struct flow_key key;
	struct flow_entry *e;
	uint64_t now_ms;
	int dir, ret;

	ff_stats.packets++;
	now_ms = ff_now_ms(h);
	flow_sweep_timeouts(now_ms, FF_SWEEP_PER_PACKET);

	if (parse_packet(ff_dlt, h, sp, &t) != 0) {
		/* Unclassifiable: fail open. */
		ff_stats.fallbacks++;
		ff_stats.passed++;
		return 1;
	}

	if (t.frag_nonfirst) {
		/*
		 * Non-initial fragment: no ports available.  Resolve the
		 * flow through the fragment map; if that fails, fail
		 * open rather than drop.
		 */
		struct frag_entry *fe = frag_lookup(&t);

		if (fe == NULL) {
			ff_stats.frag_misses++;
			ff_stats.fallbacks++;
			ff_stats.passed++;
			return 1;
		}
		fe->last_ms = now_ms;
		e = flow_lookup(&fe->flow);
		if (e == NULL) {
			/* Flow expired/evicted already: fail open. */
			ff_stats.frag_misses++;
			ff_stats.fallbacks++;
			ff_stats.passed++;
			return 1;
		}
		ff_stats.frag_hits++;
		ff_stats.flow_hits++;
		dir = (memcmp(t.src, e->key.addr[0], 16) == 0) ? 0 : 1;
		e->pkts[dir]++;
		e->last_ms = now_ms;
		lru_touch(e);
		ret = flow_apply(e, h, sp, pktno, dir,
		    t.payload, t.payload_len);
		goto out;
	}

	make_flow_key(&key, &t);
	e = flow_lookup(&key);
	if (e == NULL) {
		e = flow_create(&key, now_ms);
		if (e == NULL) {
			/* Allocation failure: fail open. */
			ff_stats.fallbacks++;
			ff_stats.passed++;
			return 1;
		}
	} else {
		ff_stats.flow_hits++;
	}

	/* Direction of this packet relative to the canonical key. */
	dir = (memcmp(t.src, key.addr[0], 16) == 0 &&
	    t.sport == key.port[0]) ? 0 : 1;
	if (e->initiator < 0)
		e->initiator = dir;
	e->pkts[dir]++;
	e->last_ms = now_ms;
	lru_touch(e);

	/* Register initial fragments so later fragments find the flow. */
	if (t.frag_more)
		frag_insert(&t, &e->key, now_ms);

	ret = flow_apply(e, h, sp, pktno, dir, t.payload, t.payload_len);
out:
	if (ret)
		ff_stats.passed++;
	else
		ff_stats.dropped++;
	return ret;
}

/* ------------------------------------------------------------------ */
/* Public API.                                                        */
/* ------------------------------------------------------------------ */

static int
dlt_supported(int dlt)
{
	switch (dlt) {
	case DLT_EN10MB:
	case DLT_RAW:
#ifdef DLT_LINUX_SLL
	case DLT_LINUX_SLL:
#endif
#ifdef DLT_LINUX_SLL2
	case DLT_LINUX_SLL2:
#endif
#ifdef DLT_NULL
	case DLT_NULL:
#endif
#if defined(DLT_LOOP) && !defined(DLT_NULL)
	case DLT_LOOP:
#endif
		return 1;
	default:
		return 0;
	}
}

int
flow_filter_init(const struct flowfilter_config *cfg, int dlt)
{
	uint32_t nb;

	ff_errstr[0] = '\0';
	if (!dlt_supported(dlt)) {
		snprintf(ff_errstr, sizeof(ff_errstr),
		    "link-layer type %d not supported by flow filter", dlt);
		return -1;
	}
	ff_cfg = *cfg;
	if (ff_cfg.max_flows == 0)
		ff_cfg.max_flows = FF_DEFAULT_MAX_FLOWS;
	if (ff_cfg.timeout_sec == 0)
		ff_cfg.timeout_sec = FF_DEFAULT_TIMEOUT_SEC;
	if (ff_cfg.flow_bufmax == 0)
		ff_cfg.flow_bufmax = FF_DEFAULT_BUFMAX;
	if (ff_cfg.prebuf_max == 0)
		ff_cfg.prebuf_max = FF_DEFAULT_PREBUF;
	if (ff_cfg.max_mem == 0)
		ff_cfg.max_mem = FF_DEFAULT_MAX_MEM;

#ifdef FF_HAVE_REGEX
	if (ff_cfg.pattern != NULL) {
		int rc = regcomp(&ff_re, ff_cfg.pattern,
		    REG_EXTENDED | REG_NOSUB);

		if (rc != 0) {
			regerror(rc, &ff_re, ff_errstr, sizeof(ff_errstr));
			return -2;
		}
		ff_re_compiled = 1;
	}
#else
	if (ff_cfg.pattern != NULL) {
		snprintf(ff_errstr, sizeof(ff_errstr),
		    "regular expression support not available in this build");
		return -2;
	}
#endif

	nb = 1024;
	while (nb < ff_cfg.max_flows && nb < (1U << 22))
		nb *= 2;
	ff_nbuckets = nb;
	ff_buckets = (struct flow_entry **)calloc(ff_nbuckets,
	    sizeof(*ff_buckets));
	if (ff_buckets == NULL) {
		snprintf(ff_errstr, sizeof(ff_errstr), "out of memory");
		return -2;
	}
	ff_frag_nbuckets = 1024;
	ff_frag_buckets = (struct frag_entry **)calloc(ff_frag_nbuckets,
	    sizeof(*ff_frag_buckets));
	if (ff_frag_buckets == NULL) {
		free(ff_buckets);
		ff_buckets = NULL;
		snprintf(ff_errstr, sizeof(ff_errstr), "out of memory");
		return -2;
	}
	ff_dlt = dlt;
	ff_inited = 1;
	return 0;
}

const char *
flow_filter_errstr(void)
{
	return ff_errstr;
}

void
flow_filter_set_emit(flowfilter_emit_cb cb, void *ctx)
{
	ff_emit_cb = cb;
	ff_emit_ctx = ctx;
}

int
flow_filter_packet(const struct pcap_pkthdr *h, const u_char *sp,
    uint64_t pktno)
{
	int ret;

	if (!ff_inited)
		return 1;
	FF_LOCK();
	ff_stats.lock_waits++;
	ret = flow_filter_packet_locked(h, sp, pktno);
	FF_UNLOCK();
	return ret;
}

void
flow_filter_get_stats(struct flowfilter_stats *st)
{
	FF_LOCK();
	*st = ff_stats;
	FF_UNLOCK();
}

void
flow_filter_print_stats(FILE *fp)
{
	struct flowfilter_stats st;

	flow_filter_get_stats(&st);
	fprintf(fp, "flow filter statistics:\n");
	fprintf(fp, "  packets: %llu presented, %llu passed, %llu suppressed\n",
	    (unsigned long long)st.packets,
	    (unsigned long long)st.passed,
	    (unsigned long long)st.dropped);
	fprintf(fp, "  flows: %llu created, %llu active, %llu flow hits\n",
	    (unsigned long long)st.flows_created,
	    (unsigned long long)st.flows_active,
	    (unsigned long long)st.flow_hits);
	fprintf(fp, "  table: %llu full events, %llu evictions, %llu timeouts\n",
	    (unsigned long long)st.table_full,
	    (unsigned long long)st.evictions,
	    (unsigned long long)st.timeouts);
	fprintf(fp, "  fragments: %llu hits, %llu misses\n",
	    (unsigned long long)st.frag_hits,
	    (unsigned long long)st.frag_misses);
	fprintf(fp, "  regex: %llu matches, %llu pre-match packets dropped (buffer cap)\n",
	    (unsigned long long)st.regex_matches,
	    (unsigned long long)st.prebuf_dropped);
	fprintf(fp, "  fallback: %llu fail-open events (packets passed as stateless)\n",
	    (unsigned long long)st.fallbacks);
	fprintf(fp, "  memory: %llu bytes current, %llu bytes peak, %llu memory-cap events\n",
	    (unsigned long long)st.mem_current,
	    (unsigned long long)st.mem_peak,
	    (unsigned long long)st.mem_cap_events);
	fprintf(fp, "  concurrency: %llu lock acquisitions\n",
	    (unsigned long long)st.lock_waits);
}

void
flow_filter_cleanup(void)
{
	uint32_t i;
	struct frag_entry *fe, *fenext;

	if (!ff_inited)
		return;
	FF_LOCK();
	while (ff_lru_head != NULL)
		flow_remove(ff_lru_head);
	free(ff_buckets);
	ff_buckets = NULL;
	for (i = 0; i < ff_frag_nbuckets; i++) {
		fe = ff_frag_buckets[i];
		while (fe != NULL) {
			fenext = fe->hnext;
			free(fe);
			fe = fenext;
		}
	}
	free(ff_frag_buckets);
	ff_frag_buckets = NULL;
#ifdef FF_HAVE_REGEX
	if (ff_re_compiled) {
		regfree(&ff_re);
		ff_re_compiled = 0;
	}
#endif
	ff_inited = 0;
	FF_UNLOCK();
}
