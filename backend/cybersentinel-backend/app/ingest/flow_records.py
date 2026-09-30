"""NetFlow v5 / v9 and IPFIX (v10) flow-record codec.

PS 26145 names "exported flow records (NetFlow/IPFIX/sFlow)" as an input.
This module turns those records into the SAME dict schema the lab replay files
use (data/pcaps/*.json), so a flow that arrives over IPFIX goes through
`_flowstate_from_json` and the detectors exactly like a replayed one.

Standard fields cover the 5-tuple, counters, timing and TCP flags. Metadata a
passive probe can derive but standard IPFIX has no element for (DNS query
name/type, JA3, ClientHello counts, packet size / timing series, scan fan-out)
travels as enterprise-specific Information Elements under PEN 32473 - the
number RFC 5612 reserves for documentation/examples - the same mechanism real
probes (nProbe, YAF) use for DNS/TLS export. With plain NetFlow v5/v9 those
fields are absent: DGA, DNS-tunnel and TLS detectors then have nothing to
score, the other modules work.

Read-only by construction: this module only parses bytes; nothing here sends.
"""
from __future__ import annotations

import socket
import struct
import time
from typing import Dict, List, Optional, Tuple

PEN = 32473

# Standard IPFIX Information Elements (same numbers as NetFlow v9 field types
# for the ones shared).
OCTETS, PACKETS, PROTO, TCP_FLAGS, SRC_PORT, SRC_V4 = 1, 2, 4, 6, 7, 8
DST_PORT, DST_V4, SRC_V6, DST_V6 = 11, 12, 27, 28
V9_LAST_SWITCHED, V9_FIRST_SWITCHED = 21, 22
START_S, END_S, START_MS, END_MS = 150, 151, 152, 153

# THREX enterprise IEs (PEN 32473).
E_DNS_QNAME, E_DNS_QTYPE, E_JA3, E_TLS_COUNTS = 1, 2, 3, 4
E_SIZE_SEQ, E_TIME_OFFSETS, E_DST_PORTS, E_UNIQ_PORTS, E_UNIQ_HOSTS = 5, 6, 7, 8, 9

VARLEN = 0xFFFF
_PROTO_NAME = {6: "tcp", 17: "udp", 1: "icmp"}
_PROTO_NUM = {v: k for k, v in _PROTO_NAME.items()}
_FLAG_BITS = ((0x02, "SYN"), (0x10, "ACK"), (0x08, "PSH"), (0x01, "FIN"), (0x04, "RST"), (0x20, "URG"))


def flags_to_names(bits: int) -> List[str]:
    return [name for bit, name in _FLAG_BITS if bits & bit]


def names_to_flags(names) -> int:
    if isinstance(names, str):
        names = [names]
    table = {n: b for b, n in _FLAG_BITS}
    table.update({"S": 0x02, "A": 0x10, "P": 0x08, "F": 0x01, "R": 0x04})
    bits = 0
    for n in names or []:
        bits |= table.get(str(n).upper(), 0)
    return bits


# --------------------------------------------------------------------- encode
# Template used by the THREX exporter: every field the detectors can use.
THREX_TEMPLATE_ID = 256
THREX_FIELDS: Tuple[Tuple[int, int, int], ...] = (   # (ie, length, pen)
    (SRC_V4, 4, 0), (DST_V4, 4, 0), (SRC_PORT, 2, 0), (DST_PORT, 2, 0), (PROTO, 1, 0),
    (TCP_FLAGS, 2, 0), (PACKETS, 8, 0), (OCTETS, 8, 0), (START_MS, 8, 0), (END_MS, 8, 0),
    (E_DNS_QTYPE, 2, PEN), (E_TLS_COUNTS, 4, PEN), (E_UNIQ_PORTS, 4, PEN), (E_UNIQ_HOSTS, 4, PEN),
    (E_DNS_QNAME, VARLEN, PEN), (E_JA3, VARLEN, PEN), (E_SIZE_SEQ, VARLEN, PEN),
    (E_TIME_OFFSETS, VARLEN, PEN), (E_DST_PORTS, VARLEN, PEN),
)
_FIXED_HEAD = struct.Struct(">4s4sHHBHQQQQHBBBBII")


def _varlen(b: bytes) -> bytes:
    n = len(b)
    return (bytes([n]) + b) if n < 255 else (b"\xff" + struct.pack(">H", n) + b)


def _template_set(template_id: int = THREX_TEMPLATE_ID, fields=THREX_FIELDS) -> bytes:
    body = struct.pack(">HH", template_id, len(fields))
    for ie, length, pen in fields:
        if pen:
            body += struct.pack(">HHI", ie | 0x8000, length, pen)
        else:
            body += struct.pack(">HH", ie, length)
    return struct.pack(">HH", 2, 4 + len(body)) + body


def encode_record(rec: dict) -> bytes:
    """Lab-schema flow dict -> one IPFIX data record for THREX_FIELDS."""
    raw = rec.get("raw_features") or {}
    start = float(rec.get("start_time", 0.0))
    end = float(rec.get("end_time", start + float(rec.get("duration_seconds", 0.0))))
    counts = (int(raw.get("ciphers_count", 0)), int(raw.get("extensions_count", 0)),
              int(raw.get("curves_count", 0)), int(raw.get("point_formats_count", 0)))
    qtype = int(rec.get("dns_qtype", 0) or 0)
    if not qtype and raw.get("txt_query_volume"):
        qtype = 16
    ts = [float(t) for t in (rec.get("timestamps") or [])][:50]
    sizes = [int(s) for s in (rec.get("packet_sizes") or [])][:50]
    ports = [int(p) for p in (rec.get("dst_ports") or [])][:256]
    head = _FIXED_HEAD.pack(
        socket.inet_aton(rec.get("src_ip", "0.0.0.0")), socket.inet_aton(rec.get("dst_ip", "0.0.0.0")),
        int(rec.get("src_port") or 0), int(rec.get("dst_port") or 0),
        _PROTO_NUM.get(str(rec.get("protocol", "tcp")).lower(), 6),
        names_to_flags(rec.get("flags")),
        int(rec.get("packet_count", 0)), int(rec.get("bytes_transferred", 0)),
        int(round(start * 1000)), int(round(end * 1000)),
        qtype, *[min(c, 255) for c in counts],
        int(raw.get("unique_dst_ports", 0) or 0), int(raw.get("unique_dst_hosts", 0) or 0),
    )
    t0 = ts[0] if ts else start
    return (head
            + _varlen((rec.get("dns_query") or "").encode())
            + _varlen((rec.get("ja3") or raw.get("ja3") or "").encode())
            + _varlen(struct.pack(f">{len(sizes)}H", *[min(max(s, 0), 65535) for s in sizes]))
            + _varlen(struct.pack(f">{len(ts)}I", *[max(0, int(round((t - t0) * 1000))) for t in ts]))
            + _varlen(struct.pack(f">{len(ports)}H", *ports)))


class IPFIXEncoder:
    """Builds IPFIX messages (RFC 7011) from lab-schema dicts. Used by the
    flow exporter and tests; the THREX backend itself never sends."""

    def __init__(self, odid: int = 1, mtu: int = 1400, template_every: int = 64):
        self.odid, self.mtu, self.template_every = odid, mtu, template_every
        self.seq = 0            # cumulative data records sent (RFC 7011 3.1)
        self._msgs = 0
        self._tset = _template_set()

    def _message(self, sets: bytes, export_time: Optional[int] = None) -> bytes:
        hdr = struct.pack(">HHIII", 10, 16 + len(sets),
                          int(export_time if export_time is not None else time.time()), self.seq, self.odid)
        return hdr + sets

    def encode(self, records: List[dict], export_time: Optional[int] = None) -> List[bytes]:
        out, batch, size = [], [], 0
        budget = self.mtu - 16 - 4 - len(self._tset)
        encoded = [encode_record(r) for r in records]
        for rec in encoded:
            if batch and size + len(rec) > budget:
                out.append(self._flush(batch, export_time)); batch, size = [], 0
            batch.append(rec); size += len(rec)
        if batch:
            out.append(self._flush(batch, export_time))
        return out

    def _flush(self, batch: List[bytes], export_time) -> bytes:
        body = b"".join(batch)
        data_set = struct.pack(">HH", THREX_TEMPLATE_ID, 4 + len(body)) + body
        sets = (self._tset if self._msgs % self.template_every == 0 else b"") + data_set
        msg = self._message(sets, export_time)
        self._msgs += 1
        self.seq = (self.seq + len(batch)) & 0xFFFFFFFF
        return msg


def encode_netflow_v5(records: List[dict], boot_time: float, seq: int = 0) -> bytes:
    """Minimal NetFlow v5 encoder (tests). <= 30 records per packet."""
    now = time.time()
    uptime = int((now - boot_time) * 1000)
    hdr = struct.pack(">HHIIIIBBH", 5, len(records), uptime, int(now), int((now % 1) * 1e9), seq, 0, 0, 0)
    body = b""
    for r in records:
        s = float(r.get("start_time", now)); e = float(r.get("end_time", s))
        body += struct.pack(">4s4s4sHHIIIIHHBBBBHHBBH",
                            socket.inet_aton(r["src_ip"]), socket.inet_aton(r["dst_ip"]), b"\0\0\0\0", 0, 0,
                            int(r.get("packet_count", 0)), int(r.get("bytes_transferred", 0)),
                            int((s - boot_time) * 1000), int((e - boot_time) * 1000),
                            int(r.get("src_port") or 0), int(r.get("dst_port") or 0), 0,
                            names_to_flags(r.get("flags")), _PROTO_NUM.get(r.get("protocol", "tcp"), 6), 0,
                            0, 0, 0, 0, 0)
    return hdr + body


# --------------------------------------------------------------------- decode
_FMT = {1: "B", 2: "H", 4: "I", 8: "Q"}


class _Template:
    __slots__ = ("fields", "fixed", "st", "names")

    def __init__(self, fields: List[Tuple[int, int, int]]):
        self.fields = fields
        self.fixed = all(length != VARLEN for _, length, _ in fields)
        self.names = [(ie, pen) for ie, _, pen in fields]
        self.st = None
        if self.fixed:
            fmt = ">" + "".join(
                ("4s" if (ie in (SRC_V4, DST_V4) and not pen and length == 4)
                 else _FMT.get(length, f"{length}s")) for ie, length, pen in fields)
            self.st = struct.Struct(fmt)


class FlowRecordDecoder:
    """Stateful decoder: templates are cached per (exporter, domain, id).

    stats: messages, records, seq_gap_records (records the exporter says it
    sent that never arrived - the loss figure for a one-way UDP feed),
    unknown_template_sets, malformed.
    """

    def __init__(self):
        self._templates: Dict[tuple, _Template] = {}
        self._next_seq: Dict[tuple, int] = {}
        self.stats = {"messages": 0, "records": 0, "seq_gap_records": 0,
                      "unknown_template_sets": 0, "malformed": 0}

    # -- public
    def decode(self, data: bytes, exporter: str = "?") -> List[dict]:
        if len(data) < 2:
            self.stats["malformed"] += 1
            return []
        version = struct.unpack_from(">H", data)[0]
        try:
            if version == 10:
                return self._ipfix(data, exporter)
            if version == 9:
                return self._v9(data, exporter)
            if version == 5:
                return self._v5(data, exporter)
        except (struct.error, IndexError, ValueError):
            self.stats["malformed"] += 1
            return []
        self.stats["malformed"] += 1
        return []

    # -- sequence accounting
    def _track(self, key, seq: int, n_records: int, per_record: bool = True):
        exp = self._next_seq.get(key)
        if exp is not None and per_record:
            gap = (seq - exp) & 0xFFFFFFFF
            if 0 < gap < 0x7FFFFFFF:
                self.stats["seq_gap_records"] += gap
        self._next_seq[key] = (seq + (n_records if per_record else 1)) & 0xFFFFFFFF

    # -- v5
    def _v5(self, data: bytes, exporter: str) -> List[dict]:
        _, count, uptime, secs, nsecs, seq = struct.unpack_from(">HHIIII", data)
        boot = secs + nsecs / 1e9 - uptime / 1000.0
        out = []
        for i in range(count):
            (src, dst, _nh, _in, _out, pkts, octs, first, last, sport, dport, _p1, flags, proto,
             _tos, _sas, _das, _sm, _dm, _p2) = struct.unpack_from(
                ">4s4s4sHHIIIIHHBBBBHHBBH", data, 24 + 48 * i)
            out.append(self._build(socket.inet_ntoa(src), socket.inet_ntoa(dst), sport, dport, proto,
                                   flags, pkts, octs, boot + first / 1000.0, boot + last / 1000.0))
        self._track((exporter, "v5"), seq, count)
        self.stats["messages"] += 1
        self.stats["records"] += len(out)
        return out

    # -- v9 / IPFIX shared set walker
    def _v9(self, data: bytes, exporter: str) -> List[dict]:
        _, _count, uptime, secs, seq, source_id = struct.unpack_from(">HHIIII", data)
        boot = secs - uptime / 1000.0
        out = self._walk_sets(data, 20, len(data), (exporter, 9, source_id), v9_boot=boot)
        self._track((exporter, 9, source_id), seq, 1, per_record=False)  # v9 counts packets
        self.stats["messages"] += 1
        self.stats["records"] += len(out)
        return out

    def _ipfix(self, data: bytes, exporter: str) -> List[dict]:
        _, length, _export, seq, odid = struct.unpack_from(">HHIII", data)
        out = self._walk_sets(data, 16, min(length, len(data)), (exporter, 10, odid))
        self._track((exporter, 10, odid), seq, len(out))
        self.stats["messages"] += 1
        self.stats["records"] += len(out)
        return out

    def _walk_sets(self, data, pos, end, domain, v9_boot=None) -> List[dict]:
        out: List[dict] = []
        ipfix = domain[1] == 10
        while pos + 4 <= end:
            set_id, set_len = struct.unpack_from(">HH", data, pos)
            if set_len < 4:
                break
            body, body_end = pos + 4, min(pos + set_len, end)
            if (ipfix and set_id == 2) or (not ipfix and set_id == 0):
                self._read_templates(data, body, body_end, domain, ipfix)
            elif set_id >= 256:
                tpl = self._templates.get((domain, set_id))
                if tpl is None:
                    self.stats["unknown_template_sets"] += 1
                else:
                    out.extend(self._read_data(data, body, body_end, tpl, v9_boot))
            pos += set_len
        return out

    def _read_templates(self, data, pos, end, domain, ipfix):
        while pos + 4 <= end:
            tid, count = struct.unpack_from(">HH", data, pos)
            pos += 4
            if tid < 256:
                break
            fields = []
            for _ in range(count):
                ie, length = struct.unpack_from(">HH", data, pos)
                pos += 4
                pen = 0
                if ipfix and ie & 0x8000:
                    ie &= 0x7FFF
                    pen = struct.unpack_from(">I", data, pos)[0]
                    pos += 4
                fields.append((ie, length, pen))
            self._templates[(domain, tid)] = _Template(fields)

    def _read_data(self, data, pos, end, tpl: _Template, v9_boot) -> List[dict]:
        out = []
        if tpl.fixed:
            size = tpl.st.size
            n = (end - pos) // size
            if n <= 0:
                return out
            for vals in tpl.st.iter_unpack(data[pos:pos + n * size]):
                out.append(self._from_fields(dict(zip(tpl.names, vals)), v9_boot))
            return out
        while pos < end:
            vals, ok = {}, True
            for ie, length, pen in tpl.fields:
                if length == VARLEN:
                    if pos >= end:
                        ok = False; break
                    n = data[pos]; pos += 1
                    if n == 255:
                        n = struct.unpack_from(">H", data, pos)[0]; pos += 2
                    vals[(ie, pen)] = data[pos:pos + n]; pos += n
                else:
                    if pos + length > end:
                        ok = False; break
                    chunk = data[pos:pos + length]; pos += length
                    if (ie in (SRC_V4, DST_V4) and not pen) or length not in _FMT:
                        vals[(ie, pen)] = chunk
                    else:
                        vals[(ie, pen)] = int.from_bytes(chunk, "big")
            if not ok:
                break  # trailing padding
            out.append(self._from_fields(vals, v9_boot))
        return out

    # -- field map -> lab-schema dict
    @staticmethod
    def _ip(v) -> str:
        if isinstance(v, (bytes, bytearray)):
            return socket.inet_ntoa(v) if len(v) == 4 else socket.inet_ntop(socket.AF_INET6, v)
        return socket.inet_ntoa(struct.pack(">I", v))

    def _from_fields(self, f: dict, v9_boot) -> dict:
        g = f.get
        src = g((SRC_V4, 0)) or g((SRC_V6, 0)) or b"\0\0\0\0"
        dst = g((DST_V4, 0)) or g((DST_V6, 0)) or b"\0\0\0\0"
        if g((START_MS, 0)) is not None:
            start, end = g((START_MS, 0)) / 1000.0, (g((END_MS, 0)) or g((START_MS, 0))) / 1000.0
        elif g((START_S, 0)) is not None:
            start, end = float(g((START_S, 0))), float(g((END_S, 0)) or g((START_S, 0)))
        elif v9_boot is not None and g((V9_FIRST_SWITCHED, 0)) is not None:
            start = v9_boot + g((V9_FIRST_SWITCHED, 0)) / 1000.0
            end = v9_boot + (g((V9_LAST_SWITCHED, 0)) or g((V9_FIRST_SWITCHED, 0))) / 1000.0
        else:
            start = end = time.time()
        rec = self._build(self._ip(src), self._ip(dst), g((SRC_PORT, 0)) or 0, g((DST_PORT, 0)) or 0,
                          g((PROTO, 0)) or 6, g((TCP_FLAGS, 0)) or 0, g((PACKETS, 0)) or 0,
                          g((OCTETS, 0)) or 0, start, end)
        if not f.get((E_DNS_QNAME, PEN)) and (E_DNS_QNAME, PEN) not in f and (E_TLS_COUNTS, PEN) not in f:
            return rec
        raw = rec["raw_features"]
        qn = g((E_DNS_QNAME, PEN))
        if qn:
            rec["dns_query"] = bytes(qn).decode("utf-8", "replace")
        qt = g((E_DNS_QTYPE, PEN))
        if qt:
            rec["dns_qtype"] = int(qt)
        ja3 = g((E_JA3, PEN))
        if ja3:
            rec["ja3"] = bytes(ja3).decode("ascii", "replace")
        tc = g((E_TLS_COUNTS, PEN))
        if tc:
            c = tc.to_bytes(4, "big") if isinstance(tc, int) else bytes(tc)
            if any(c):
                raw["ciphers_count"], raw["extensions_count"], raw["curves_count"], raw["point_formats_count"] = c
        sz = g((E_SIZE_SEQ, PEN))
        if sz:
            rec["packet_sizes"] = list(struct.unpack(f">{len(sz) // 2}H", bytes(sz)[: len(sz) // 2 * 2]))
        to = g((E_TIME_OFFSETS, PEN))
        if to:
            offs = struct.unpack(f">{len(to) // 4}I", bytes(to)[: len(to) // 4 * 4])
            rec["timestamps"] = [start + o / 1000.0 for o in offs]
        dp = g((E_DST_PORTS, PEN))
        if dp:
            rec["dst_ports"] = list(struct.unpack(f">{len(dp) // 2}H", bytes(dp)[: len(dp) // 2 * 2]))
        up, uh = g((E_UNIQ_PORTS, PEN)), g((E_UNIQ_HOSTS, PEN))
        if up:
            raw["unique_dst_ports"] = int(up)
        if uh:
            raw["unique_dst_hosts"] = int(uh)
        return rec

    @staticmethod
    def _build(src, dst, sport, dport, proto, flags, pkts, octs, start, end) -> dict:
        return {
            "src_ip": src, "dst_ip": dst, "src_port": int(sport), "dst_port": int(dport),
            "protocol": _PROTO_NAME.get(int(proto), "tcp"), "flags": flags_to_names(int(flags)),
            "packet_count": int(pkts), "bytes_transferred": int(octs),
            "start_time": float(start), "end_time": float(end),
            "duration_seconds": max(0.0, float(end) - float(start)), "raw_features": {},
        }
