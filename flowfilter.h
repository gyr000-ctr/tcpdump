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
 * Stateful flow-based filtering for tcpdump.
 *
 * This module supplements the stateless BPF filter with a flow table
 * keyed by the 5-tuple (IP version, addresses, protocol, ports).  It
 * can pass only the first packet / first N packets of every flow, pass
 * only packets of flows whose payload matches a regular expression and
 * restrict matching to one direction of a flow.
 *
 * The design is fail-open: any internal problem (unsupported link
 * layer, truncated packet, memory cap, table pressure that cannot be
 * relieved) makes the filter pass the packet exactly as the stateless
 * BPF filter would, rather than silently dropping it.  Every such
 * event is counted in the statistics.
 *
 * All resources are bounded: the flow table has a hard cap on the
 * number of entries, per-flow payload/packet buffers have hard caps
 * and the total buffer memory has a hard cap.  No unbounded per-packet
 * allocation takes place.
 */
#ifndef FLOWFILTER_H
#define FLOWFILTER_H

#include <stdint.h>
#include <stdio.h>
#include <pcap.h>

/* Direction selector for --flow-dir. */
#define FLOW_DIR_BOTH	0	/* both directions (default) */
#define FLOW_DIR_FWD	1	/* initiator -> responder only */
#define FLOW_DIR_REV	2	/* responder -> initiator only */

struct flowfilter_config {
	uint64_t first_n;	/* if > 0, pass only the first N packets
				   of every flow (1 = first packet only) */
	const char *pattern;	/* if not NULL, POSIX ERE matched against
				   the per-direction payload byte stream;
				   packets of matching flows pass (including
				   buffered pre-match packets, bounded) */
	int dir;		/* FLOW_DIR_* */
	uint32_t max_flows;	/* flow table capacity (hard bound) */
	uint32_t timeout_sec;	/* idle flow timeout, 0 = default */
	uint32_t flow_bufmax;	/* per-flow payload scan buffer cap (bytes) */
	uint32_t prebuf_max;	/* per-flow pre-match packet buffer cap
				   (bytes, regex mode) */
	uint64_t max_mem;	/* global cap for all dynamic buffer
				   memory (bytes) */
	int audit;		/* log flow lifecycle events to stderr */
};

/* Counters, all monotonically increasing except mem_current. */
struct flowfilter_stats {
	uint64_t packets;	/* packets presented to the filter */
	uint64_t passed;	/* packets the filter passed */
	uint64_t dropped;	/* packets the filter suppressed */
	uint64_t flows_created;	/* flow table entries created */
	uint64_t flows_active;	/* entries currently in the table */
	uint64_t flow_hits;	/* packets attributed to existing flows */
	uint64_t table_full;	/* times the table was found full */
	uint64_t evictions;	/* LRU evictions to make room */
	uint64_t timeouts;	/* idle timeout expirations */
	uint64_t fallbacks;	/* fail-open events (packet passed) */
	uint64_t frag_hits;	/* non-first fragments matched to a flow */
	uint64_t frag_misses;	/* non-first fragments with unknown flow */
	uint64_t regex_matches;	/* flows whose payload matched */
	uint64_t prebuf_dropped;/* pre-match packets dropped (buffer cap) */
	uint64_t mem_cap_events;/* times the global memory cap was hit */
	uint64_t mem_current;	/* bytes of buffer memory in use now */
	uint64_t mem_peak;	/* high-water mark of mem_current */
	uint64_t lock_waits;	/* mutex acquisitions (concurrency metric) */
};

/*
 * Callback used to re-emit packets that were buffered before a flow
 * matched (regex mode).  pktno is the capture number the packet had
 * when it was first seen.
 */
typedef void (*flowfilter_emit_cb)(void *ctx, const struct pcap_pkthdr *h,
    const u_char *sp, uint64_t pktno);

/*
 * Initialise the flow filter.  dlt is the data link type of the
 * capture.  Returns 0 on success, -1 if the link layer is not
 * supported (caller should warn and run stateless), -2 on a
 * configuration error (e.g. a bad regular expression).
 */
int flow_filter_init(const struct flowfilter_config *cfg, int dlt);

/* Error message for the most recent failed flow_filter_init(). */
const char *flow_filter_errstr(void);

/* Register the callback used to emit buffered packets. */
void flow_filter_set_emit(flowfilter_emit_cb cb, void *ctx);

/*
 * Process one packet.  Returns 1 if the packet must be passed
 * (printed/dumped) and 0 if it must be suppressed.  Never fails
 * closed: any internal error returns 1 and counts a fallback.
 * pktno is the current capture packet number (for -# printing of
 * buffered packets).
 */
int flow_filter_packet(const struct pcap_pkthdr *h, const u_char *sp,
    uint64_t pktno);

/* Fetch a snapshot of the statistics. */
void flow_filter_get_stats(struct flowfilter_stats *st);

/* Print human-readable statistics/audit metrics. */
void flow_filter_print_stats(FILE *fp);

/* Tear down and release all resources. */
void flow_filter_cleanup(void);

#endif /* FLOWFILTER_H */
