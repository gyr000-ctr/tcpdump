#!/usr/bin/env python3
# Generate the pcap files used by the flow-filter tests in TESTLIST.
# Usage: make-flow-test-pcaps.py <output-directory>
#
# Writes: flow-basic.pcap, flow-regex.pcap, flow-frag.pcap, flow-full.pcap
#
# All packets are Ethernet/IPv4 with correct IP and TCP/UDP checksums and
# fixed timestamps (2026-01-01 00:00:00 GMT + 10 ms per packet) so the
# tcpdump output is deterministic under TZ=GMT0 (as TESTrun sets it).

import struct
import sys

BASE_TS = 1767225600  # 2026-01-01 00:00:00 GMT


def cksum(data):
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) | data[i + 1]
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def ipv4(src, dst, proto, payload, ident=0, frag_off=0, mf=False):
    ver_ihl = 0x45
    total = 20 + len(payload)
    flags_frag = (0x2000 if mf else 0) | frag_off
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident,
                      flags_frag, 64, proto, 0,
                      bytes(src), bytes(dst))
    c = cksum(hdr)
    hdr = struct.pack("!BBHHHBBH4s4s", ver_ihl, 0, total, ident,
                      flags_frag, 64, proto, c,
                      bytes(src), bytes(dst))
    return hdr + payload


def tcp(src, dst, sport, dport, seq, flags, payload=b""):
    doff_flags = (5 << 12) | flags
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0,
                      doff_flags >> 8, doff_flags & 0xFF, 8192, 0, 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack("!BBH", 0, 6,
                                                   len(hdr) + len(payload))
    c = cksum(pseudo + hdr + payload)
    hdr = struct.pack("!HHIIBBHHH", sport, dport, seq, 0,
                      doff_flags >> 8, doff_flags & 0xFF, 8192, c, 0)
    return hdr + payload


def udp(src, dst, sport, dport, payload):
    length = 8 + len(payload)
    hdr = struct.pack("!HHHH", sport, dport, length, 0)
    pseudo = bytes(src) + bytes(dst) + struct.pack("!BBH", 0, 17, length)
    c = cksum(pseudo + hdr + payload)
    hdr = struct.pack("!HHHH", sport, dport, length, c)
    return hdr + payload


def eth(ip_packet):
    return b"\x02\x00\x00\x00\x00\x02" + b"\x02\x00\x00\x00\x00\x01" + \
        b"\x08\x00" + ip_packet


class Pcap:
    def __init__(self):
        self.pkts = []

    def add(self, data):
        # 10 ms per packet, in arrival order.
        ts = BASE_TS + len(self.pkts) // 100
        us = (len(self.pkts) % 100) * 10000
        self.pkts.append((ts, us, data))

    def write(self, path):
        with open(path, "wb") as f:
            f.write(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0,
                                65535, 1))  # LINKTYPE_ETHERNET
            for ts, us, data in self.pkts:
                f.write(struct.pack("<IIII", ts, us, len(data), len(data)))
                f.write(data)


A1 = (10, 0, 0, 1)
A2 = (10, 0, 0, 2)
B1 = (10, 0, 0, 3)
B2 = (10, 0, 0, 4)
C1 = (10, 0, 0, 5)
C2 = (10, 0, 0, 6)


def make_basic():
    """Two TCP flows and one UDP flow, interleaved."""
    p = Pcap()
    # 1: flow A fwd SYN
    p.add(eth(ipv4(A1, A2, 6, tcp(A1, A2, 12345, 80, 1000, 0x02))))
    # 2: flow B fwd SYN
    p.add(eth(ipv4(B1, B2, 6, tcp(B1, B2, 2222, 3333, 2000, 0x02))))
    # 3: flow A rev SYN-ACK
    p.add(eth(ipv4(A2, A1, 6, tcp(A2, A1, 80, 12345, 5000, 0x12))))
    # 4: flow A fwd ACK
    p.add(eth(ipv4(A1, A2, 6, tcp(A1, A2, 12345, 80, 1001, 0x10))))
    # 5: flow C fwd UDP
    p.add(eth(ipv4(C1, C2, 17, udp(C1, C2, 40000, 40001, b"query-one"))))
    # 6: flow B fwd ACK
    p.add(eth(ipv4(B1, B2, 6, tcp(B1, B2, 2222, 3333, 2001, 0x10))))
    # 7: flow A fwd PSH data
    p.add(eth(ipv4(A1, A2, 6, tcp(A1, A2, 12345, 80, 1002, 0x18,
                                  b"hello-flow-a"))))
    # 8: flow B rev data
    p.add(eth(ipv4(B2, B1, 6, tcp(B2, B1, 3333, 2222, 7000, 0x18,
                                  b"reply-flow-b"))))
    # 9: flow C fwd UDP
    p.add(eth(ipv4(C1, C2, 17, udp(C1, C2, 40000, 40001, b"query-two"))))
    # 10: flow A fwd FIN
    p.add(eth(ipv4(A1, A2, 6, tcp(A1, A2, 12345, 80, 1014, 0x11))))
    # 11: flow B fwd FIN
    p.add(eth(ipv4(B1, B2, 6, tcp(B1, B2, 2222, 3333, 2002, 0x11))))
    return p


X1 = (192, 168, 1, 10)
X2 = (192, 168, 1, 20)
Y1 = (192, 168, 1, 11)


def make_regex():
    """Two TCP sessions; only flow X carries the secret_token pattern."""
    p = Pcap()
    # Flow X: 192.168.1.10:40000 -> 192.168.1.20:8080
    p.add(eth(ipv4(X1, X2, 6, tcp(X1, X2, 40000, 8080, 100, 0x02))))
    # Flow Y: 192.168.1.11:50000 -> 192.168.1.20:443
    p.add(eth(ipv4(Y1, X2, 6, tcp(Y1, X2, 50000, 443, 900, 0x02))))
    p.add(eth(ipv4(X1, X2, 6, tcp(X1, X2, 40000, 8080, 101, 0x18,
                                  b"GET /index.html HTTP/1.0\r\n"))))
    p.add(eth(ipv4(Y1, X2, 6, tcp(Y1, X2, 50000, 443, 901, 0x18,
                                  b"GET /public HTTP/1.0\r\n"))))
    p.add(eth(ipv4(X2, X1, 6, tcp(X2, X1, 8080, 40000, 8000, 0x10))))
    p.add(eth(ipv4(X1, X2, 6, tcp(X1, X2, 40000, 8080, 130, 0x18,
                                  b"X-Token: secret_token_123\r\n"))))
    p.add(eth(ipv4(Y1, X2, 6, tcp(Y1, X2, 50000, 443, 925, 0x18,
                                  b"benign data\r\n"))))
    p.add(eth(ipv4(X1, X2, 6, tcp(X1, X2, 40000, 8080, 158, 0x18,
                                  b"more data\r\n"))))
    p.add(eth(ipv4(X1, X2, 6, tcp(X1, X2, 40000, 8080, 169, 0x11))))
    p.add(eth(ipv4(Y1, X2, 6, tcp(Y1, X2, 50000, 443, 937, 0x11))))
    return p


F1 = (10, 1, 1, 1)
F2 = (10, 1, 1, 2)
G1 = (10, 2, 2, 1)
G2 = (10, 2, 2, 2)


def make_frag():
    """A fragmented UDP datagram, a normal UDP flow and an orphan
    non-initial fragment (unknown flow -> fail-open pass)."""
    p = Pcap()
    # 32-byte UDP payload; the FRAGPATTERN string straddles the first
    # fragment boundary (first fragment carries 16 data bytes).
    data = b"x" * 12 + b"FRAGPATTERN" + b"y" * 9
    assert len(data) == 32
    udp_pkt = udp(F1, F2, 1111, 2222, data)
    ident = 0x1234
    # Fragment 1: offset 0, 24 bytes of IP payload (UDP hdr + 16 data), MF.
    p.add(eth(ipv4(F1, F2, 17, udp_pkt[:24], ident=ident, frag_off=0,
                   mf=True)))
    # A normal unfragmented UDP flow in between.
    p.add(eth(ipv4(G1, G2, 17, udp(G1, G2, 5000, 5001, b"normal-flow"))))
    # Fragment 2: offset 24, 8 bytes, MF.
    p.add(eth(ipv4(F1, F2, 17, udp_pkt[24:32], ident=ident, frag_off=24,
                   mf=True)))
    # Fragment 3: offset 32, 8 bytes, last.
    p.add(eth(ipv4(F1, F2, 17, udp_pkt[32:40], ident=ident, frag_off=32)))
    # Orphan non-initial fragment: no first fragment was ever seen for
    # this (addresses, protocol, ID) tuple, so the filter must fail open
    # and pass it.
    p.add(eth(ipv4(G1, G2, 17, b"orphan!!", ident=0x9999, frag_off=8)))
    return p


def make_full():
    """Six TCP flows, three packets each, interleaved round-robin; used
    with --flow-max 4 to exercise table-full eviction."""
    p = Pcap()
    hosts = [((10, 9, 0, i), (10, 9, 9, i)) for i in range(1, 7)]
    for rnd in range(3):
        for i, (h1, h2) in enumerate(hosts):
            sport = 30000 + i
            seq = 1000 + rnd
            flags = 0x02 if rnd == 0 else 0x10
            p.add(eth(ipv4(h1, h2, 6,
                           tcp(h1, h2, sport, 80, seq, flags))))
    return p


def main():
    outdir = sys.argv[1]
    make_basic().write(outdir + "/flow-basic.pcap")
    make_regex().write(outdir + "/flow-regex.pcap")
    make_frag().write(outdir + "/flow-frag.pcap")
    make_full().write(outdir + "/flow-full.pcap")


if __name__ == "__main__":
    main()
