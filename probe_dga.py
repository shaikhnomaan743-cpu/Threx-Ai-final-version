#!/usr/bin/env python
"""Temporary probe: reproduce the DGA diode-loss anomaly at 0% loss."""
import asyncio, json, os, sys
from pathlib import Path

BE = Path(r"C:\Users\shaik\OneDrive\Desktop\threx-AI\backend\cybersentinel-backend")
sys.path.insert(0, str(BE))
os.chdir(BE)

from app.inference.engine import InferenceEngine
from app.ingest.pcap_reader import _flowstate_from_json

DGA = Path(r"C:\Users\shaik\OneDrive\Desktop\threx-AI\data\pcaps\attacks\dga_queries.json")
BENIGN = Path(r"C:\Users\shaik\OneDrive\Desktop\threx-AI\data\pcaps\benign\benign_tcp.json")


async def main():
    e = InferenceEngine()
    await e.initialize_models()
    print("detectors:", list(e.detectors))
    print("dga model loaded:", e._model_loaded.get("dga"),
          "dga detector is None?:", e.detectors.get("dga") is None)

    dga_rows = json.loads(DGA.read_text())
    benign_rows = json.loads(BENIGN.read_text())

    print("\n--- DGA flows, NO loss ---")
    hit = miss = 0
    beacon_on_dga = 0
    for r in dga_rows:
        fs = _flowstate_from_json(r)
        if fs is None:
            print("  null flowstate for", r.get("flow_id"))
            continue
        a = await e.analyze_flow(fs)
        cls = [x.threat_class for x in a]
        if "c2_beacon" in cls:
            beacon_on_dga += 1
        if any(c in ("dga", "dns_tunnel") for c in cls):
            hit += 1
        else:
            miss += 1
            if miss <= 3:
                print("  MISS", r["flow_id"], "domain=", fs.dns_query,
                      "alerts=", cls, "raw=", r.get("raw_features"))
    print("DGA hits(dga/dns_tunnel)=", hit, "miss=", miss, "total=", len(dga_rows))
    print("DGA flows ALSO firing c2_beacon =", beacon_on_dga)

    print("\n--- BENIGN tcp flows, NO loss (should not fire dns/dga/beacon) ---")
    dga_fp = dns_fp = beacon_fp = 0
    for r in benign_rows:
        fs = _flowstate_from_json(r)
        if fs is None:
            continue
        a = await e.analyze_flow(fs)
        cls = [x.threat_class for x in a]
        if "dga" in cls:
            dga_fp += 1
        if "dns_tunnel" in cls:
            dns_fp += 1
        if "c2_beacon" in cls:
            beacon_fp += 1
        if any(c in ("dga", "dns_tunnel", "c2_beacon") for c in cls):
            print("  benign fired", r["flow_id"], cls, "dns_query=", repr(getattr(fs, 'dns_query', '')))
    print("benign dga_fp=", dga_fp, "dns_fp=", dns_fp, "beacon_fp=", beacon_fp,
          "total=", len(benign_rows))


asyncio.run(main())
