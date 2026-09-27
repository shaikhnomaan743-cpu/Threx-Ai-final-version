"""Fast, dependency-free PCAP / PCAPNG reader (replaces scapy on the file path).

scapy dissects every layer into Python objects (~5,300 packets/s measured);
this reads only the headers the detectors use with `struct`, which is an
order of magnitude faster. It also fixes three gaps in the scapy path:

  * DNS names were only extracted from TCP packets - DNS over UDP (nearly all
    of it) never reached the DGA / DNS-tunnel detectors. Parsed here for UDP
    and TCP port 53.
  * "ja3" held the TLS version or four cipher ids, not a JA3. Here it is the
    standard JA3 (MD5 of version,ciphers,extensions,curves,point-formats with
    GREASE removed) from the ClientHello, plus the four ClientHello counts the
    TLS classifier reads.
  * Query names were rendered as "b'example.com.'".

Metadata only: payload bytes are inspected solely to read a DNS question and
the ClientHello header fields; nothing is decrypted or stored.
Link types: Ethernet (+802.1Q), Linux cooked v1/v2, raw IP, BSD loopback.
A ClientHello split across TCP segments is not reassembled (JA3 left empty).
"""
from __future__ import annotations

import hashlib
import socket
import struct
from typing import Iterator, Optional, Tuple

from app.ingest.pcap_reader import PacketInfo

_GREASE = {0x0a0a + 0x1010 * i for i in range(16)}
_TCP_FLAG_LETTERS = ((0x01, "F"), (0x02, "S"), (0x04, "R"), (0x08, "P"), (0x10, "A"), (0x20, "U"))
_FLAG_CACHE = {}
_PROTO = {6: "tcp", 17: "udp", 1: "icmp", 58: "icmp"}


def _flags(bits: int) -> str:
    s = _FLAG_CACHE.get(bits)
    if s is None:  # same letter order scapy prints: F S R P A U
        s = _FLAG_CACHE[bits] = "".join(ch for b, ch in _TCP_FLAG_LETTERS if bits & b)
    return s


# ------------------------------------------------------------------- DNS / TLS
def parse_dns_question(msg: bytes) -> Tuple[str, int]:
    """First question name and type of a DNS message ("" , 0 if absent)."""
    if len(msg) < 17 or struct.unpack_from(">H", msg, 4)[0] == 0:
        return "", 0
    pos, labels = 12, []
    while pos < len(msg):
        n = msg[pos]
        if n == 0:
            pos += 1
            break
        if n & 0xC0:          # compression pointer: not expected in a question
            return "", 0
        labels.append(msg[pos + 1:pos + 1 + n].decode("ascii", "replace"))
        pos += 1 + n
    if pos + 2 > len(msg):
        return "", 0
    return ".".join(labels), struct.unpack_from(">H", msg, pos)[0]


def parse_client_hello(p: bytes) -> Optional[Tuple[str, Tuple[int, int, int, int]]]:
    """(JA3 md5, (n_ciphers, n_extensions, n_curves, n_point_formats)) or None."""
    if len(p) < 11 or p[0] != 0x16 or p[1] != 0x03 or p[5] != 0x01:
        return None
    try:
        pos = 9                                   # record(5) + handshake type(1) + len(3)
        version = struct.unpack_from(">H", p, pos)[0]
        pos += 2 + 32                             # client_version + random
        pos += 1 + p[pos]                         # session id
        clen = struct.unpack_from(">H", p, pos)[0]
        ciphers = [c for c in struct.unpack_from(f">{clen // 2}H", p, pos + 2) if c not in _GREASE]
        pos += 2 + clen
        pos += 1 + p[pos]                         # compression methods
        exts, curves, pfmts = [], [], []
        if pos + 2 <= len(p):
            end = min(len(p), pos + 2 + struct.unpack_from(">H", p, pos)[0])
            pos += 2
            while pos + 4 <= end:
                etype, elen = struct.unpack_from(">HH", p, pos)
                body = p[pos + 4:pos + 4 + elen]
                if etype not in _GREASE:
                    exts.append(etype)
                    if etype == 10 and len(body) >= 2:          # supported_groups
                        n = struct.unpack_from(">H", body)[0] // 2
                        curves = [g for g in struct.unpack_from(f">{n}H", body, 2) if g not in _GREASE]
                    elif etype == 11 and body:                  # ec_point_formats
                        pfmts = list(body[1:1 + body[0]])
                pos += 4 + elen
        ja3 = ",".join([str(version), "-".join(map(str, ciphers)), "-".join(map(str, exts)),
                        "-".join(map(str, curves)), "-".join(map(str, pfmts))])
        return hashlib.md5(ja3.encode()).hexdigest(), (len(ciphers), len(exts), len(curves), len(pfmts))
    except (struct.error, IndexError):
        return None


# ------------------------------------------------------------------- packets
def _l3(link: int, buf: bytes) -> Optional[Tuple[int, int]]:
    """(ethertype-ish: 4 or 6, offset of IP header)."""
    if link == 1:                                 # Ethernet
        if len(buf) < 14:
            return None
        et, off = struct.unpack_from(">H", buf, 12)[0], 14
        while et in (0x8100, 0x88A8) and len(buf) >= off + 4:
            et, off = struct.unpack_from(">H", buf, off + 2)[0], off + 4
    elif link == 113:                             # Linux cooked v1
        if len(buf) < 16:
            return None
        et, off = struct.unpack_from(">H", buf, 14)[0], 16
    elif link == 276:                             # Linux cooked v2
        if len(buf) < 20:
            return None
        et, off = struct.unpack_from(">H", buf, 0)[0], 20
    elif link in (101, 12, 14, 228, 229):         # raw IP
        if not buf:
            return None
        v = buf[0] >> 4
        return (4 if v == 4 else 6 if v == 6 else 0), 0
    elif link == 0:                               # BSD loopback
        if len(buf) < 4:
            return None
        fam = struct.unpack_from("<I", buf)[0]
        return (4 if fam == 2 else 6 if fam in (24, 28, 30) else 0), 4
    else:
        return None
    return (4 if et == 0x0800 else 6 if et == 0x86DD else 0), off


def packet_info(link: int, ts: float, buf: bytes, wire_len: int) -> Optional[PacketInfo]:
    l3 = _l3(link, buf)
    if l3 is None or not l3[0]:
        return None
    ver, off = l3
    if ver == 4:
        if len(buf) < off + 20:
            return None
        ihl = (buf[off] & 0x0F) * 4
        proto = buf[off + 9]
        src, dst = socket.inet_ntoa(buf[off + 12:off + 16]), socket.inet_ntoa(buf[off + 16:off + 20])
        l4 = off + ihl
    else:
        if len(buf) < off + 40:
            return None
        proto = buf[off + 6]
        src = socket.inet_ntop(socket.AF_INET6, buf[off + 8:off + 24])
        dst = socket.inet_ntop(socket.AF_INET6, buf[off + 24:off + 40])
        l4 = off + 40
    sport = dport = 0
    flags, dns_q, dns_t, ja3, counts = "", "", 0, "", None
    if proto == 6 and len(buf) >= l4 + 20:
        sport, dport, _s, _a, doff, fl = struct.unpack_from(">HHIIBB", buf, l4)
        flags = _flags(fl)
        payload = buf[l4 + (doff >> 4) * 4:]
        if payload:
            if sport == 53 or dport == 53:
                dns_q, dns_t = parse_dns_question(payload[2:])          # 2-byte length prefix
            elif payload[0] == 0x16:
                ch = parse_client_hello(payload)
                if ch:
                    ja3, counts = ch
    elif proto == 17 and len(buf) >= l4 + 8:
        sport, dport = struct.unpack_from(">HH", buf, l4)
        if sport == 53 or dport == 53:
            dns_q, dns_t = parse_dns_question(buf[l4 + 8:])
    elif proto not in (1, 58):
        return None
    return PacketInfo(src_ip=src, dst_ip=dst, src_port=sport, dst_port=dport, protocol=_PROTO.get(proto, "tcp"),
                      timestamp=ts, flags=flags, ja3=ja3, dns_query=dns_q, dns_qtype=dns_t,
                      packet_size=wire_len, tls_counts=counts)


# ------------------------------------------------------------------- files
def iter_pcap(path: str) -> Iterator[PacketInfo]:
    with open(path, "rb") as fh:
        head = fh.read(24)
        if len(head) < 4:
            return
        magic = head[:4]
        if magic == b"\x0a\x0d\x0d\x0a":
            fh.seek(0)
            yield from _iter_pcapng(fh)
            return
        if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
            e = "<"
        elif magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
            e = ">"
        else:
            raise ValueError("not a pcap/pcapng file")
        nano = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        link = struct.unpack_from(e + "I", head, 20)[0] & 0x0FFFFFFF
        rec = struct.Struct(e + "IIII")
        div = 1e9 if nano else 1e6
        while True:
            h = fh.read(16)
            if len(h) < 16:
                return
            sec, frac, incl, orig = rec.unpack(h)
            buf = fh.read(incl)
            if len(buf) < incl:
                return
            p = packet_info(link, sec + frac / div, buf, orig)
            if p is not None:
                yield p


def _iter_pcapng(fh) -> Iterator[PacketInfo]:
    e, ifaces = "<", []
    while True:
        hdr = fh.read(8)
        if len(hdr) < 8:
            return
        btype = struct.unpack_from("<I", hdr)[0]
        if btype == 0x0A0D0D0A:
            bom = fh.read(4)
            e = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            blen = struct.unpack_from(e + "I", hdr, 4)[0]
            fh.read(blen - 12)
            ifaces = []
            continue
        btype, blen = struct.unpack_from(e + "II", hdr)
        body = fh.read(blen - 8)
        if len(body) < blen - 8:
            return
        if btype == 1:                                           # interface description
            link = struct.unpack_from(e + "H", body)[0]
            res = 1e6
            pos = 8
            while pos + 4 <= len(body) - 4:
                code, olen = struct.unpack_from(e + "HH", body, pos)
                if code == 0:
                    break
                if code == 9 and olen >= 1:                      # if_tsresol
                    v = body[pos + 4]
                    res = float(2 ** (v & 0x7F)) if v & 0x80 else float(10 ** v)
                pos += 4 + ((olen + 3) & ~3)
            ifaces.append((link, res))
        elif btype == 6 and ifaces:                              # enhanced packet
            iid, hi, lo, incl, orig = struct.unpack_from(e + "IIIII", body)
            link, res = ifaces[iid] if iid < len(ifaces) else ifaces[0]
            p = packet_info(link, ((hi << 32) | lo) / res, body[20:20 + incl], orig)
            if p is not None:
                yield p
        elif btype == 3 and ifaces:                              # simple packet
            orig = struct.unpack_from(e + "I", body)[0]
            link, _ = ifaces[0]
            p = packet_info(link, 0.0, body[4:4 + min(orig, len(body) - 8)], orig)
            if p is not None:
                yield p
