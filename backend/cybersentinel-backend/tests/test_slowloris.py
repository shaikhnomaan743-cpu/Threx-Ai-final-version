"""Slow-rate DoS detector: fires on concurrent steady-trickle sockets to one
web server, stays quiet on idle keep-alive and on a single slow socket."""
from app.models.slowloris_detector import SlowRateDoSDetector
from app.ingest.pcap_reader import FlowState


def _flow(i, src="198.51.100.7", dst="203.0.113.50", port=80, start=1000.0,
          dur=200.0, gap=12.0, size=70, silent_tail=False):
    f = FlowState(key=f"k{i}", src_ip=src, dst_ip=dst, protocol="tcp", src_port=40000 + i, dst_port=port)
    t = [start + j * gap for j in range(int(dur // gap) + 1)]
    if silent_tail:
        t = [start + j * 0.05 for j in range(6)] + [start + dur]
    f.timestamps, f.packet_sizes = t, [size] * len(t)
    f.packet_count, f.bytes_transferred = len(t), size * len(t)
    f.start_time, f.end_time = t[0], t[-1]
    return f


def test_fires_on_many_concurrent_slow_sockets():
    d = SlowRateDoSDetector()
    hits = [d.detect(_flow(i, start=1000 + i * 0.1)) for i in range(30)]
    assert hits[6] is None and hits[7] is not None          # gate: 8 concurrent
    assert hits[-1]["threat_class"] == "ddos"
    assert hits[-1]["model_version"] == "slow_rate_dos_v1"


def test_quiet_on_idle_keepalive_even_when_concurrent():
    d = SlowRateDoSDetector()
    assert all(d.detect(_flow(i, port=443, silent_tail=True, start=1000 + i)) is None for i in range(200))


def test_quiet_on_single_slow_socket_and_non_web_port():
    d = SlowRateDoSDetector()
    assert d.detect(_flow(0)) is None
    d2 = SlowRateDoSDetector()
    assert all(d2.detect(_flow(i, port=22, start=1000 + i)) is None for i in range(30))
