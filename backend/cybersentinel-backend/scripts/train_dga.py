#!/usr/bin/env python3
"""Train the DGA classifier on real corpora (DGArchive-derived + Tranco).

Replaces the previous synthetic generator, whose "malicious" domains were
random strings produced inside the script. In that corpus every DGA label was
>= 12 characters and 98% of benign labels were < 12, so a single length
threshold solved the task and the reported AUC of 1.0 measured the dataset,
not the model.

Three numbers are reported so the length confound stays visible:

  1. length-only baseline  - AUC using domain_length as the sole feature.
     Watch this one. If it is near 1.0 the corpus is still length-confounded
     and nothing else in the report means anything.
  2. full model            - all 8 features including domain_length.
  3. length-ablated model  - the same model with domain_length removed.

The deployed artifact is the length-ablated model. The full model is trained
only so the gap between (2) and (3) can be quoted.

Usage:
    cd backend/cybersentinel-backend
    PYTHONPATH=. python3 scripts/train_dga.py
"""
from __future__ import annotations

import csv, json, os, random, statistics, sys, time
from pathlib import Path
import numpy as np

sys.path.insert(0, os.getcwd())
from app.models.dga_classifier import extract_dga_domain_features  # noqa: E402

try:
    import lightgbm as lgb
except ImportError:
    print("ERROR: LightGBM not installed. Run: pip install lightgbm")
    sys.exit(1)

from sklearn.metrics import roc_auc_score, confusion_matrix  # noqa: E402
from sklearn.model_selection import StratifiedKFold, train_test_split  # noqa: E402

SEED = 42
random.seed(SEED); np.random.seed(SEED)

REPO_ROOT = Path(__file__).resolve().parents[3]
DATA_DIR = REPO_ROOT / "backend" / "data"
DGA_CSV = DATA_DIR / "dga_domains.csv"
TRANCO_CSV = DATA_DIR / "top-1m.csv"
ARTIFACT_DIR = Path("app/models/artifacts")
EVAL_OUT = DATA_DIR / "dga_evaluation.json"

FEATURE_NAMES = ["domain_entropy","bigram_log_likelihood_2","bigram_log_likelihood_3",
                 "consonant_vowel_ratio","digit_ratio","domain_length","tld_length",
                 "has_dictionary_word"]
LENGTH_IDX = FEATURE_NAMES.index("domain_length")

PARAMS = {"objective":"binary","metric":"auc","boosting_type":"gbdt","learning_rate":0.05,
          "num_leaves":31,"feature_fraction":0.8,"bagging_fraction":0.8,"bagging_freq":5,
          "verbosity":-1,"seed":SEED}


def featurise(domain: str):
    f = extract_dga_domain_features(domain)
    return [float(f["domain_entropy"]), float(f["bigram_log_likelihood_2"]),
            float(f["bigram_log_likelihood_3"]), float(f["consonant_vowel_ratio"]),
            float(f["digit_ratio"]), float(f["domain_length"]), float(f["tld_length"]),
            1.0 if f["has_dictionary_word"] else 0.0]


def load_corpus(tranco_n: int = 40000):
    if not DGA_CSV.exists():
        raise SystemExit(f"Missing {DGA_CSV}")
    benign, malicious, families = [], [], {}
    with open(DGA_CSV, newline="") as fh:
        for row in csv.DictReader(fh):
            label = (row.get("domain") or "").strip().lower()
            if not label:
                continue
            if row.get("class") == "dga":
                malicious.append(label)
                fam = row.get("subclass") or "unknown"
                families[fam] = families.get(fam, 0) + 1
            else:
                benign.append(label)
    if TRANCO_CSV.exists():
        extra = []
        with open(TRANCO_CSV, newline="", encoding="utf-8", errors="ignore") as fh:
            for row in csv.reader(fh):
                if len(row) < 2:
                    continue
                label = row[1].strip().lower().split(".")[0]
                if label:
                    extra.append(label)
                if len(extra) >= tranco_n:
                    break
        benign.extend(extra)
        print(f"  Tranco benign added: {len(extra)}")
    benign = list(dict.fromkeys(benign)); malicious = list(dict.fromkeys(malicious))
    print(f"  DGA families: {families}")
    return benign, malicious


def length_report(benign, malicious):
    lb = [len(d) for d in benign]; lm = [len(d) for d in malicious]
    rep = {"benign_len_mean": round(statistics.mean(lb),2), "benign_len_median": statistics.median(lb),
           "benign_len_min": min(lb), "benign_len_max": max(lb),
           "dga_len_mean": round(statistics.mean(lm),2), "dga_len_median": statistics.median(lm),
           "dga_len_min": min(lm), "dga_len_max": max(lm)}
    lo = max(rep["benign_len_min"], rep["dga_len_min"]); hi = min(rep["benign_len_max"], rep["dga_len_max"])
    rep["length_overlap_benign_pct"] = round(sum(1 for x in lb if lo<=x<=hi)/len(lb)*100,1)
    rep["length_overlap_dga_pct"] = round(sum(1 for x in lm if lo<=x<=hi)/len(lm)*100,1)
    return rep


def cv_auc(X, y, folds=5):
    scores = []
    for tr, te in StratifiedKFold(n_splits=folds, shuffle=True, random_state=SEED).split(X, y):
        m = lgb.train(PARAMS, lgb.Dataset(X[tr], label=y[tr]), num_boost_round=200,
                      callbacks=[lgb.log_evaluation(0)])
        scores.append(roc_auc_score(y[te], m.predict(X[te])))
    return float(statistics.mean(scores)), float(statistics.pstdev(scores))


def main():
    print("="*64); print("DGA CLASSIFIER — training on real corpora"); print("="*64)
    print("\n[1/6] Loading corpora...")
    benign, malicious = load_corpus()
    print(f"  Benign: {len(benign)} | DGA: {len(malicious)}")

    print("\n[2/6] Length distribution (the previous failure mode)...")
    lrep = length_report(benign, malicious)
    for k, v in lrep.items(): print(f"  {k}: {v}")

    print("\n[3/6] Extracting features...")
    X = np.array([featurise(d) for d in benign] + [featurise(d) for d in malicious], dtype=float)
    y = np.array([0]*len(benign) + [1]*len(malicious))
    print(f"  Feature matrix: {X.shape}")

    print("\n[4/6] Length-only baseline (diagnostic)...")
    len_mean, len_sd = cv_auc(X[:, [LENGTH_IDX]], y)
    print(f"  length-only CV AUC: {len_mean:.4f} (+/- {len_sd:.4f})")
    if len_mean > 0.95:
        print("  WARNING: corpus still length-separable; other metrics unreliable.")

    print("\n[5/6] Full model vs length-ablated model...")
    full_mean, full_sd = cv_auc(X, y)
    print(f"  full (8 features)       CV AUC: {full_mean:.4f} (+/- {full_sd:.4f})")
    keep = [i for i in range(X.shape[1]) if i != LENGTH_IDX]
    X_abl = X[:, keep]
    abl_mean, abl_sd = cv_auc(X_abl, y)
    print(f"  length-ablated (7 feat) CV AUC: {abl_mean:.4f} (+/- {abl_sd:.4f})")
    print(f"  cost of removing length: {abl_mean - full_mean:+.4f} AUC")

    print("\n[6/6] Training deployed model (length-ablated)...")
    Xtr, Xte, ytr, yte = train_test_split(X_abl, y, test_size=0.2, random_state=SEED, stratify=y)
    clf = lgb.train(PARAMS, lgb.Dataset(Xtr, label=ytr), num_boost_round=200,
                    valid_sets=[lgb.Dataset(Xte, label=yte)], callbacks=[lgb.log_evaluation(0)])
    test_pred = clf.predict(Xte)
    test_auc = roc_auc_score(yte, test_pred)
    tn, fp, fn, tp = confusion_matrix(yte, (test_pred > 0.5).astype(int)).ravel()
    print(f"  trees: {clf.num_trees()} | test AUC: {test_auc:.4f}")
    print(f"  TN={tn} FP={fp} FN={fn} TP={tp}")
    print(f"  TPR: {tp/max(tp+fn,1):.2%} | FPR: {fp/max(tn+fp,1):.2%}")

    ARTIFACT_DIR.mkdir(parents=True, exist_ok=True)
    import joblib; joblib.dump(clf, ARTIFACT_DIR / "dga_classifier.joblib")

    report = {
        "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "corpus": {"benign_n": len(benign), "dga_n": len(malicious),
                   "benign_sources": ["dga_domains.csv (legit rows)", "Tranco top-1m"],
                   "dga_source": "dga_domains.csv (DGArchive-derived)", **lrep},
        "length_only_baseline_cv_auc": round(len_mean,4),
        "length_only_baseline_cv_sd": round(len_sd,4),
        "full_model_cv_auc": round(full_mean,4),
        "length_ablated_cv_auc": round(abl_mean,4),
        "length_ablated_cv_sd": round(abl_sd,4),
        "deployed_model": "length-ablated",
        "deployed_features": [n for i,n in enumerate(FEATURE_NAMES) if i != LENGTH_IDX],
        "deployed_test_auc": round(float(test_auc),4),
        "deployed_trees": clf.num_trees(),
        "confusion": {"tn":int(tn),"fp":int(fp),"fn":int(fn),"tp":int(tp)},
        "seed": SEED,
    }
    EVAL_OUT.write_text(json.dumps(report, indent=2))
    print(f"\n  Model  -> {ARTIFACT_DIR/'dga_classifier.joblib'}")
    print(f"  Report -> {EVAL_OUT}")
    print("="*64)


if __name__ == "__main__":
    main()
