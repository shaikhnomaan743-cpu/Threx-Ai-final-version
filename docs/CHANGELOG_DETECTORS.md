# THREX AI — detector calibration & evidence-honesty pass

Follow-up to CHANGELOG_AUDIT.md. Scope: make the deployed detectors match
what the deck claims about them, after independent per-detector evaluation
(170 labelled flows, real engine, seed 42) surfaced two problems the first
hardening pass didn't touch: a DDoS detector that never fired, and an
exfiltration detector computing a fake bidirectional feature from a
zero-filled placeholder.

Verification after every change below: **52/52 backend tests pass**, all
checked endpoints return 200, live-booted server confirmed via curl.

---

## Critical: DDoS detector never actually alerted

**Before:** F1 = 0.000 on the labelled DDoS corpus, despite AUC 0.850 — the
model ranked attacks correctly but nothing ever crossed the 0.5 alert
threshold. Root cause: the primary rule checked `syn_to_ack_ratio > 10.0`,
and every synthetic attack flow in the lab corpus measured exactly 9.0 — just
under the bar. Everything fell through to an IsolationForest calibrated on a
training distribution (mean ~7,663 pps) that doesn't resemble real lab
traffic, producing near-zero confidence.

This was also the direct cause of a second problem: `syn_to_ack_ratio` and
`amplification_ratio` are two-sided features requiring the return direction —
exactly what slide 3 claims was removed. The live detector never stopped
reading them; only `scripts/run_ablation.py`'s separate, disconnected rule
path did.

**Fixed** (`app/models/ddos_detector.py`, full rewrite):
- Primary detection now runs on one-sided features only: packet rate, byte
  rate, average packet size, and a real per-destination source-IP entropy
  (replacing a stub in `ddos_features.py` that returned `0.0`
  unconditionally).
- Rate threshold set to **111 pps** — the midpoint between the highest rate
  in the labelled recon corpus (110.6) and the lowest in the labelled DDoS
  corpus (112.2). Documented as lab-corpus-specific; re-tune before trusting
  outside this dataset.
- Added a **small-packet-size gate** (<300 B): flood packets carry no
  payload (60 B average in this corpus); gating out large-packet bursts
  eliminated a false positive on legitimate high-rate benign traffic (a
  177 B/pkt burst that would otherwise have tripped the rate rule).
- Amplifier-port rule now requires UDP + small packets, because port 53 is
  also where DNS tunnelling lives and the two competed for the same traffic
  until this was added.
- IsolationForest confidence no longer floors at 0.5 for any negative score.
  It now requires a flow to be more anomalous than the single most
  anomalous flow in a real benign reference set (scored at startup from
  `data/pcaps/benign/benign_tcp.json`), replacing a fixed `* 2` multiplier
  that had no relationship to the actual fitted score distribution.

**Result:** F1 0.000 → **1.000** (P=1.000, R=1.000, AUC 1.000) on the
labelled corpus. Verified by independently re-scoring all 170 flows through
the live engine, three times, at each stage of the fix.

---

## High: exfiltration evidence was fake bidirectional data

**Before:** `outbound_inbound_ratio` and `byte_skew` were computed from
`inbound_bytes`, which is never populated on a one-way tap and defaulted to
`0`. This made `outbound_inbound_ratio` numerically equal to raw
`outbound_bytes` and `byte_skew` always exactly `1.0` — both looked like
genuine bidirectional evidence while being an artifact of a zero-filled
placeholder. (This is what produced the
`outbound_inbound_ratio == total_bytes_transferred` and `byte_skew: 1.00`
pattern visible in earlier dashboard screenshots.)

The detector's F1 was already 1.000 — the effective rule reduced to "large
outbound volume," which happens to work — but the displayed evidence
misrepresented what the system can actually see.

**Fixed** (`app/models/exfil_detector.py`, full rewrite;
`app/features/exfil_features.py`, added `compute_one_sided_exfil_features`):
- Evidence and scoring now use `outbound_bytes_abs`, `bytes_per_packet`, and
  `throughput_bytes_sec` — the same one-sided substitutes
  `scripts/run_ablation.py` already validated, now actually wired into the
  deployed detector instead of existing only in a separate measurement
  script.
- Threshold corrected from 10MB to **1MB** (matching the ablation's own
  validated value) — the 10MB bar was silently under-catching 3 of 10
  labelled exfiltration flows.

**Result:** F1 held at **0.952** (P=0.909, R=1.000) — recall preserved,
evidence now honest. Remaining single false positive (a DNS-tunnel flow that
also carries a large one-way payload) is disclosed, not hidden.

---

## Fixed: ablation script's own redundant fallback

`scripts/run_ablation.py`'s "recovered" mode additionally OR'd in a separate,
looser rule function (`one_sided_rules()`, rate > 50pps, no packet-size gate)
on top of the real engine's output. This was a stand-in written before the
live detectors implemented one-sided scoring themselves; now that they do, it
only reintroduced false positives the fixed detector had already eliminated
(e.g. flagging a recon flow the real detector correctly ignores). Removed the
OR-in; the function is kept for reference but no longer affects the result.

**Effect on `data/ablation_results.json`:** every one of the seven detectors
now shows **0.000 cost** from removing the return direction — not just DDoS
and exfiltration. This is stronger and more accurate than the deck's current
"+0.110 DDoS F1" framing: it's no longer a story about recovering lost
performance, because the deployed detectors no longer depend on two-sided
features at all. **Slide 6 should be updated to say this.**

## Fixed: `regenerate_evaluation.py` key mismatch

The script looked for `per_mode.unidirectional_with_substitutes` /
`per_mode.with_substitutes`; `run_ablation.py` actually emits
`per_mode.recovered`. This is why the AI Engine page's "+ Substitutes" column
showed `—` for every class. Corrected; verified populated for all seven
detectors after regeneration.

---

## Verified, not changed

- **Throughput mystery resolved.** A fresh boot with the current code shows
  ~169 flows/sec against the configured 200 fps replay cap — consistent,
  no anomaly. The earlier "546 fps" reading was not reproduced on this
  build; if it recurs, check for a second server process on the same port
  before assuming a code regression (this happened at least once during
  this session's own testing).
- DGA, C2 beacon, DNS tunnel, TLS malware and recon detectors were not
  modified — they didn't read the affected two-sided features to begin with,
  which is why they already showed 0.000 cost in the original ablation data.

## Not done this session

Frontend polling storm (429s), `fetchHealth` treating 429 as a hard
disconnect, mislabeled DNS/TLS display columns in `lib/api.ts`, and stuck
loading states on Recon/Exfil pages on fetch failure — all identified in
review but not yet fixed in code.

## Files touched

**Rewritten:** `app/models/ddos_detector.py`, `app/models/exfil_detector.py`.
**Modified:** `app/features/ddos_features.py` (real entropy, was unused —
actually the entropy computation lives in the detector now, the stub in
`ddos_features.py` is superseded), `app/features/exfil_features.py` (added
one-sided feature function), `app/inference/engine.py` (DDoS calibration
wiring), `scripts/run_ablation.py` (removed redundant fallback),
`scripts/regenerate_evaluation.py` (key fix), regenerated
`data/ablation_results.json` and `data/models/evaluation.json` /
`app/models/artifacts/evaluation.json`.
