/*
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code
 * distributions retain the above copyright notice and this paragraph
 * in its entirety, and (2) distributions including binary code include
 * the above copyright notice and this paragraph in its entirety in
 * the documentation or other materials provided with the distribution.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND
 * WITHOUT ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, WITHOUT
 * LIMITATION, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE.
 */

/* \summary: WireGuard printer */

/*
 * specification:
 * https://www.wireguard.com/papers/wireguard.pdf
 * https://www.wireguard.com/protocol/
 *
 * All WireGuard messages are carried in UDP datagrams and begin with a
 * 1-byte message type followed by 3 reserved bytes that must be zero:
 *
 *     0                   1                   2                   3
 *     0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |     type      |               reserved (zero)                 |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * type 1: handshake initiation (148 bytes)
 *    sender index (4, LE) | unencrypted ephemeral (32) |
 *    encrypted static (48) | encrypted timestamp (28) | mac1 (16) | mac2 (16)
 *
 * type 2: handshake response (92 bytes)
 *    sender index (4, LE) | receiver index (4, LE) |
 *    unencrypted ephemeral (32) | encrypted nothing (16) | mac1 (16) | mac2 (16)
 *
 * type 3: cookie reply (64 bytes)
 *    receiver index (4, LE) | nonce (24) | encrypted cookie (32)
 *
 * type 4: transport data (>= 32 bytes, multiple of 16)
 *    receiver index (4, LE) | counter (8, LE) | encrypted packet (N)
 *
 * The encrypted fields are never decrypted here; they are only reported
 * by length and, at higher verbosity levels, as raw hex.
 */

#include <config.h>

#include "netdissect-stdinc.h"

#define ND_LONGJMP_FROM_TCHECK
#include "netdissect.h"
#include "extract.h"

#include "udp.h"

#define WG_MSG_INITIATION	1
#define WG_MSG_RESPONSE		2
#define WG_MSG_COOKIE		3
#define WG_MSG_DATA		4

#define WG_HDR_LEN		4	/* type + reserved */
#define WG_INITIATION_LEN	148
#define WG_RESPONSE_LEN		92
#define WG_COOKIE_LEN		64
#define WG_DATA_HDR_LEN		16	/* type/reserved + receiver + counter */
#define WG_DATA_MIN_LEN		32	/* header + one AEAD tag (keepalive) */
#define WG_MAC_LEN		16

/* Field offsets in a handshake initiation message. */
#define WG_INIT_SENDER_OFF	4
#define WG_INIT_EPHEMERAL_OFF	8
#define WG_INIT_EPHEMERAL_LEN	32
#define WG_INIT_STATIC_OFF	40
#define WG_INIT_STATIC_LEN	48
#define WG_INIT_TIMESTAMP_OFF	88
#define WG_INIT_TIMESTAMP_LEN	28
#define WG_INIT_MAC1_OFF	116
#define WG_INIT_MAC2_OFF	132

/* Field offsets in a handshake response message. */
#define WG_RESP_SENDER_OFF	4
#define WG_RESP_RECEIVER_OFF	8
#define WG_RESP_EPHEMERAL_OFF	12
#define WG_RESP_EPHEMERAL_LEN	32
#define WG_RESP_EMPTY_OFF	44
#define WG_RESP_EMPTY_LEN	16
#define WG_RESP_MAC1_OFF	60
#define WG_RESP_MAC2_OFF	76

/* Field offsets in a cookie reply message. */
#define WG_COOKIE_RECEIVER_OFF	4
#define WG_COOKIE_NONCE_OFF	8
#define WG_COOKIE_NONCE_LEN	24
#define WG_COOKIE_COOKIE_OFF	32
#define WG_COOKIE_COOKIE_LEN	32

/* Field offsets in a transport data message. */
#define WG_DATA_RECEIVER_OFF	4
#define WG_DATA_COUNTER_OFF	8
#define WG_DATA_PAYLOAD_OFF	16

/*
 * Tell whether a UDP payload looks like a WireGuard message.  The
 * message type and the zero reserved bytes are always required; the
 * datagram length is then cross-checked against the fixed message
 * sizes.  Packets to or from the well-known WireGuard port are claimed
 * even when the length is non-standard, so that malformed traffic on
 * that port is reported as such instead of falling back to plain UDP.
 */
int
wireguard_detect(netdissect_options *ndo, const u_char *bp, u_int length,
		 u_int sport, u_int dport)
{
	uint8_t type;

	if (length < WG_HDR_LEN)
		return 0;
	/* Do not touch captured data beyond the snapshot. */
	if (!ND_TTEST_LEN(bp, WG_HDR_LEN))
		return 0;
	/* The 3 reserved bytes must be zero. */
	if (GET_U_1(bp + 1) != 0 || GET_U_1(bp + 2) != 0 ||
	    GET_U_1(bp + 3) != 0)
		return 0;
	type = GET_U_1(bp);
	switch (type) {
	case WG_MSG_INITIATION:
		if (length == WG_INITIATION_LEN)
			return 1;
		break;
	case WG_MSG_RESPONSE:
		if (length == WG_RESPONSE_LEN)
			return 1;
		break;
	case WG_MSG_COOKIE:
		if (length == WG_COOKIE_LEN)
			return 1;
		break;
	case WG_MSG_DATA:
		if (length >= WG_DATA_MIN_LEN && (length % 16) == 0)
			return 1;
		break;
	default:
		/* Unknown type: not WireGuard, even on the WG port. */
		return 0;
	}
	/*
	 * A known message type with a non-standard length: claim it only
	 * on the well-known port.
	 */
	if (sport == WIREGUARD_PORT || dport == WIREGUARD_PORT)
		return 1;
	return 0;
}

static int
wg_all_zero(netdissect_options *ndo, const u_char *bp, u_int len)
{
	u_int i;

	for (i = 0; i < len; i++) {
		if (GET_U_1(bp + i) != 0)
			return 0;
	}
	return 1;
}

static void
wg_print_hex(netdissect_options *ndo, const u_char *bp, u_int len)
{
	u_int i;

	for (i = 0; i < len; i++)
		ND_PRINT("%02x", GET_U_1(bp + i));
}

static void
wg_print_macs(netdissect_options *ndo, const u_char *mac1, const u_char *mac2)
{
	ND_PRINT(", mac1 %s", wg_all_zero(ndo, mac1, WG_MAC_LEN) ?
		 "absent" : "present");
	if (ndo->ndo_vflag > 0 && !wg_all_zero(ndo, mac1, WG_MAC_LEN)) {
		ND_PRINT(" (0x");
		wg_print_hex(ndo, mac1, WG_MAC_LEN);
		ND_PRINT(")");
	}
	ND_PRINT(", mac2 %s", wg_all_zero(ndo, mac2, WG_MAC_LEN) ?
		 "absent" : "present");
	if (ndo->ndo_vflag > 0 && !wg_all_zero(ndo, mac2, WG_MAC_LEN)) {
		ND_PRINT(" (0x");
		wg_print_hex(ndo, mac2, WG_MAC_LEN);
		ND_PRINT(")");
	}
}

static void
wireguard_initiation_print(netdissect_options *ndo, const u_char *bp,
			   u_int length)
{
	ND_PRINT("handshake initiation");
	if (length != WG_INITIATION_LEN) {
		ND_PRINT(", invalid length %u (expected %u)",
			 length, WG_INITIATION_LEN);
		return;
	}
	ND_PRINT(", sender 0x%08x", GET_LE_U_4(bp + WG_INIT_SENDER_OFF));
	/* The timestamp is a Tai64N value, AEAD-encrypted; never decrypted. */
	ND_PRINT(", encrypted-timestamp present");
	wg_print_macs(ndo, bp + WG_INIT_MAC1_OFF, bp + WG_INIT_MAC2_OFF);
	if (ndo->ndo_vflag > 0) {
		ND_PRINT("\n\t ephemeral 0x");
		wg_print_hex(ndo, bp + WG_INIT_EPHEMERAL_OFF,
			     WG_INIT_EPHEMERAL_LEN);
	}
	if (ndo->ndo_vflag > 1) {
		ND_PRINT("\n\t encrypted-static 0x");
		wg_print_hex(ndo, bp + WG_INIT_STATIC_OFF, WG_INIT_STATIC_LEN);
		ND_PRINT("\n\t encrypted-timestamp 0x");
		wg_print_hex(ndo, bp + WG_INIT_TIMESTAMP_OFF,
			     WG_INIT_TIMESTAMP_LEN);
	}
}

static void
wireguard_response_print(netdissect_options *ndo, const u_char *bp,
			 u_int length)
{
	ND_PRINT("handshake response");
	if (length != WG_RESPONSE_LEN) {
		ND_PRINT(", invalid length %u (expected %u)",
			 length, WG_RESPONSE_LEN);
		return;
	}
	ND_PRINT(", sender 0x%08x, receiver 0x%08x",
		 GET_LE_U_4(bp + WG_RESP_SENDER_OFF),
		 GET_LE_U_4(bp + WG_RESP_RECEIVER_OFF));
	wg_print_macs(ndo, bp + WG_RESP_MAC1_OFF, bp + WG_RESP_MAC2_OFF);
	if (ndo->ndo_vflag > 0) {
		ND_PRINT("\n\t ephemeral 0x");
		wg_print_hex(ndo, bp + WG_RESP_EPHEMERAL_OFF,
			     WG_RESP_EPHEMERAL_LEN);
	}
	if (ndo->ndo_vflag > 1) {
		ND_PRINT("\n\t encrypted-empty 0x");
		wg_print_hex(ndo, bp + WG_RESP_EMPTY_OFF, WG_RESP_EMPTY_LEN);
	}
}

static void
wireguard_cookie_print(netdissect_options *ndo, const u_char *bp,
		       u_int length)
{
	ND_PRINT("cookie reply");
	if (length != WG_COOKIE_LEN) {
		ND_PRINT(", invalid length %u (expected %u)",
			 length, WG_COOKIE_LEN);
		return;
	}
	ND_PRINT(", receiver 0x%08x", GET_LE_U_4(bp + WG_COOKIE_RECEIVER_OFF));
	if (ndo->ndo_vflag > 0) {
		ND_PRINT("\n\t nonce 0x");
		wg_print_hex(ndo, bp + WG_COOKIE_NONCE_OFF, WG_COOKIE_NONCE_LEN);
	}
	if (ndo->ndo_vflag > 1) {
		ND_PRINT("\n\t encrypted-cookie 0x");
		wg_print_hex(ndo, bp + WG_COOKIE_COOKIE_OFF,
			     WG_COOKIE_COOKIE_LEN);
	}
}

static void
wireguard_data_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	ND_PRINT("transport data");
	if (length < WG_DATA_MIN_LEN || (length % 16) != 0) {
		ND_PRINT(", invalid length %u", length);
		return;
	}
	ND_PRINT(", receiver 0x%08x, counter %" PRIu64,
		 GET_LE_U_4(bp + WG_DATA_RECEIVER_OFF),
		 GET_LE_U_8(bp + WG_DATA_COUNTER_OFF));
	if (length == WG_DATA_MIN_LEN)
		ND_PRINT(", keepalive");
	else
		ND_PRINT(", length %u", length - WG_DATA_HDR_LEN);
	if (ndo->ndo_vflag > 1 && length > WG_DATA_MIN_LEN) {
		ND_PRINT("\n\t encrypted-payload[0..15] 0x");
		wg_print_hex(ndo, bp + WG_DATA_PAYLOAD_OFF, 16);
	}
}

void
wireguard_print(netdissect_options *ndo, const u_char *bp, u_int length)
{
	uint8_t type;

	ndo->ndo_protocol = "wireguard";
	ND_ICHECK_U(length, <, WG_HDR_LEN);
	type = GET_U_1(bp);
	if (GET_U_1(bp + 1) != 0 || GET_U_1(bp + 2) != 0 ||
	    GET_U_1(bp + 3) != 0) {
		ND_PRINT("WireGuard, reserved field not zero");
		goto invalid;
	}
	ND_PRINT("WireGuard, ");
	switch (type) {
	case WG_MSG_INITIATION:
		wireguard_initiation_print(ndo, bp, length);
		break;
	case WG_MSG_RESPONSE:
		wireguard_response_print(ndo, bp, length);
		break;
	case WG_MSG_COOKIE:
		wireguard_cookie_print(ndo, bp, length);
		break;
	case WG_MSG_DATA:
		wireguard_data_print(ndo, bp, length);
		break;
	default:
		ND_PRINT("unknown message type %u, length %u", type, length);
		break;
	}
	return;

invalid:
	nd_print_invalid(ndo);
}
