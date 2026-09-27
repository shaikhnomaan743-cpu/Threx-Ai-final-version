"""Worker-side coalescing must leave AlertManager in the same state as
feeding it every detection one by one."""
from datetime import datetime, timezone


def _alert(i, src, conf, feat):
    from app.alerts.schema import Alert, Evidence
    return Alert(alert_id=f"c{i}", timestamp=datetime.now(timezone.utc), flow_id=f"f{i}",
                 threat_class="ddos", severity="medium", confidence=conf, source_ip=src,
                 destination_ip="10.9.9.9", protocol="tcp", bytes_transferred=1, packet_count=1,
                 duration_seconds=0.1, model_version="t",
                 evidence=[Evidence(feature_name=feat, value=1, contribution=0.5, description="d")])


def _batch():
    return [_alert(i, "1.1.1.%d" % (i % 3), 0.5 + (i % 7) / 20, f"f{i % 4}") for i in range(60)]


def _state(m):
    out = {}
    for a in m.get_active_alerts():
        out[(a.source_ip, a.destination_ip)] = (a.alert_id, a.confidence, a.severity,
                                                sorted(e.feature_name for e in a.evidence))
    return out, dict(m._threat_counts)


def test_coalesced_equals_sequential(monkeypatch, tmp_path):
    from app.db import session
    import app.alerts.writer as w
    monkeypatch.setattr(session, "DB_PATH", str(tmp_path / "a.db"))
    monkeypatch.setattr(w, "_writer", None)
    from app.alerts.manager import AlertManager
    from app.ingest.parallel import coalesce_alerts
    seq = AlertManager()
    for a in _batch():
        seq.add_alert(a)
    co = AlertManager()
    reps = coalesce_alerts(_batch(), AlertManager())
    assert len(reps) == 3
    for a in reps:
        co.add_alert(a)
    assert _state(seq) == _state(co)
    assert co._threat_counts["ddos"] == 60
