"""Regression tests for ingest correctness and alert persistence.

Added after a refactor silently broke JSON flow loading while the rest of the
suite stayed green: these pin the behaviours the throughput work relies on.
"""
import json
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[3]
LAB = REPO / "data" / "pcaps" / "mixed" / "lab_mixed.json"


def test_json_flow_file_loads_every_entry():
    from app.ingest.pcap_reader import parse_json_flow_file
    entries = json.loads(LAB.read_text())
    flows = parse_json_flow_file(str(LAB))
    assert len(flows) == len(entries) > 0


def test_flowstate_series_are_capped():
    from app.ingest.pcap_reader import FlowState, PacketInfo, _SERIES_CAP
    f = FlowState(key="k", src_ip="1.1.1.1", dst_ip="2.2.2.2", protocol="tcp", src_port=1, dst_port=2)
    for i in range(_SERIES_CAP * 5):
        f.add_packet(PacketInfo(src_ip="1.1.1.1", dst_ip="2.2.2.2", src_port=1, dst_port=2,
                                protocol="tcp", packet_size=60, timestamp=1000.0 + i, flags="S"))
    assert f.packet_count == _SERIES_CAP * 5          # counters stay exact
    assert len(f.timestamps) == len(f.packet_sizes) == len(f._packets) == _SERIES_CAP


def test_flow_exported_once_on_fin_and_idle():
    from app.ingest.flow_builder import FlowBuilder
    from app.ingest.pcap_reader import PacketInfo
    fb, t = FlowBuilder(), 1_000_000.0

    def pkt(sport, flags, ts):
        return PacketInfo(src_ip="10.0.0.1", dst_ip="10.0.0.2", src_port=sport, dst_port=80,
                          protocol="tcp", packet_size=100, timestamp=ts, flags=flags)
    fb.add_packet(pkt(1111, "PA", t)); fb.add_packet(pkt(1111, "FA", t + 0.5))
    fb.add_packet(pkt(2222, "PA", t))
    first = fb.export_ready(now=t + 1)
    assert [f.src_port for f in first] == [1111]      # closed flow only
    assert fb.export_ready(now=t + 2) == []           # never re-exported
    idle = fb.export_ready(now=t + 60)
    assert [f.src_port for f in idle] == [2222] and fb.count() == 0


@pytest.fixture
def temp_db(monkeypatch, tmp_path):
    from app.db import session
    path = str(tmp_path / "alerts.db")
    monkeypatch.setattr(session, "DB_PATH", path)
    import app.alerts.writer as w
    monkeypatch.setattr(w, "_writer", None)
    return path


def _alert(i, src):
    from app.alerts.schema import Alert, Evidence
    return Alert(alert_id=f"t{i}", timestamp=datetime.now(timezone.utc), flow_id=f"f{i}",
                 threat_class="ddos", severity="high", confidence=0.9, source_ip=src,
                 destination_ip="10.9.9.9", protocol="tcp", bytes_transferred=1, packet_count=1,
                 duration_seconds=0.1, model_version="test",
                 evidence=[Evidence(feature_name="x", value=1, contribution=0.5, description="d")])


def test_alerts_persist_and_survive_restart(temp_db):
    from app.alerts.manager import AlertManager
    m = AlertManager()
    for i in range(500):
        m.add_alert(_alert(i, f"10.0.{i // 256}.{i % 256}"))
    assert m.flush(timeout=10)
    assert sqlite3.connect(temp_db).execute("select count(*) from alerts").fetchone()[0] == 500
    assert AlertManager().load_from_db(limit=10_000) == 500


def test_dedup_merges_and_active_set_is_bounded(temp_db):
    from app.alerts.manager import AlertManager
    m = AlertManager(max_history=1000)
    a, b = m.add_alert(_alert(1, "1.1.1.1")), m.add_alert(_alert(2, "1.1.1.1"))
    assert a.alert_id == b.alert_id
    for i in range(3000):
        m.add_alert(_alert(10 + i, f"10.1.{i // 256}.{i % 256}"))
    assert len(m.get_active_alerts()) <= m.max_active
