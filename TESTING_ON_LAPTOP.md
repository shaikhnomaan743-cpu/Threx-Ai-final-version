# Testing everything on the Legion (i7-14650HX, Windows)

Do these in order. Each step says what "pass" looks like. Paste any failure
output back into the chat.

## 0. Prepare
- Unzip `threx-changed-files.zip` over the repo root (paths are preserved).
- Laptop **plugged in**, **Fn+Q -> Performance** (red light). Close other apps.
- `cd backend/cybersentinel-backend` and `pip install -r requirements.txt`
  (no new dependencies; scipy comes with scikit-learn).

## 1. Correctness (about 5 min)
```
python -m pytest -q                                   # pass: 75 passed
set PYTHONPATH=.
python scripts/check_detection_regression.py          # pass: PASS
python scripts/evaluate_detectors.py --skip-dga --shards 12   # C2 ~74.5%, FPR ~1.7%, same as single-process
```

## 2. Throughput — the number for the slide
```
set PYTHONPATH=.
python scripts/benchmark_pipeline.py --rate 120000 --seconds 60 --mix realistic
python scripts/benchmark_pipeline.py --rate 120000 --seconds 60 --mix lab
```
Pass = `MET`: sustained >= 120,000 flows/s, p95 <= 250 ms, all loss counters 0.
If NOT MET, find the ceiling and the best worker count:
```
python scripts/benchmark_pipeline.py --rate 150000 --seconds 30 --workers 12
python scripts/benchmark_pipeline.py --rate 150000 --seconds 30 --workers 16
python scripts/benchmark_pipeline.py --rate 150000 --seconds 30 --workers 20
```
(When offered load exceeds capacity, "sustained" shows the real ceiling and
the loss counters show where it broke.) Send back the `data/benchmark_*.json` files.

## 3. The app with the multi-core pipeline + dashboard
```
set CYBERSENTINEL_FLOW_LISTEN_PORT=4739
set CYBERSENTINEL_PARALLEL_WORKERS=12
python -m uvicorn app.main:app --port 8000          # NOT --reload with workers
```
In a second terminal: `python scripts/flow_exporter.py --rate 50000 --seconds 120 --mix realistic`
Open the frontend -> System page: Pipeline "12 workers", latency p95, loss 0,
alerts appearing; no 429 errors in the backend log for 3+ minutes.

## 4. Docker
From repo root: `docker compose up --build` -> both containers healthy.
