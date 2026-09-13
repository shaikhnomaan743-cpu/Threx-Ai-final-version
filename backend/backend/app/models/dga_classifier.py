#!/usr/bin/env python3
import numpy as np
import pandas as pd
from typing import Dict, List, Any, Optional, Tuple

try:
    import lightgbm as lgb
    LIGHTGBM_AVAILABLE = True
except ImportError:
    LIGHTGBM_AVAILABLE = False

from app.features.dga_features import extract_dga_features
from app.utils.entropy import shannon_entropy


def load_alexa_top_1m(cache_path: str = "data/models/alexa_top_1m.txt") -> List[str]:
    import os
    try:
        if os.path.exists(cache_path):
            with open(cache_path, "r") as f:
                domains = [line.strip().lower() for line in f if line.strip()]
            return domains[:10000]
    except Exception:
        pass
    benign_domains = []
    for i in range(1000):
        prefixes = ["mail", "secure", "update", "api", "auth", "my", "web","app", "info", "cdn", "static", "cdn1", "cdn2"]
        suffixes = ["com", "org", "net", "io", "co"]
        domain = f"{np.random.choice(prefixes)}{np.random.randint(1000, 9999)}.{np.random.choice(suffixes)}"
        benign_domains.append(domain)
    return benign_domains


def load_dgarchive_samples(cache_path: str = "data/models/dgarchive_samples.txt") -> List[str]:
    import os
    try:
        if os.path.exists(cache_path):
            with open(cache_path, "r") as f:
                domains = [line.strip().lower() for line in f if line.strip()]
            return domains[:5000]
    except Exception:
        pass
    dga_domains = []
    import random
    random.seed(42)
    tlds = ["com", "org", "net", "info", "biz"]
    for _ in range(5000):
        length = random.randint(8, 20)
        chars = ""
        for i in range(length):
            if i % 3 == 0:
                chars += chr(random.randint(97, 122))
            elif i % 3 == 1:
                chars += chr(random.randint(48, 57))
            else:
                chars += chr(random.randint(65, 90))
        dga_list = list(chars)
        random.shuffle(dga_list)
        domain = "".join(dga_list) + "." + random.choice(tlds)
        while shannon_entropy(domain.encode("utf-8")) < 3.5:
            dga_list = list(chars)
            random.shuffle(dga_list)
            domain = "".join(dga_list) + "." + random.choice(tlds)
        dga_domains.append(domain.lower())
    return dga_domains


def extract_dga_domain_features(domain: str) -> dict:
    return extract_dga_features(domain)


def train_dga_model(
    benign_domains: List[str],
    malicious_domains: List[str],
    output_dir: str = "app/models/artifacts",
) -> Tuple[Any, float, float]:
    if not LIGHTGBM_AVAILABLE:
        raise ImportError("LightGBM not installed. Run: pip install lightgbm")
    import lightgbm as lgb
    X_benign = []
    for domain in benign_domains:
        features = extract_dga_domain_features(domain)
        X_benign.append([
            features["domain_entropy"],
            features["bigram_log_likelihood_2"],
            features["bigram_log_likelihood_3"],
            features["consonant_vowel_ratio"],
            features["digit_ratio"],
            features["domain_length"],
            features["tld_length"],
            1 if features["has_dictionary_word"] else 0,
        ])
    X_malicious = []
    for domain in malicious_domains:
        features = extract_dga_domain_features(domain)
        X_malicious.append([
            features["domain_entropy"],
            features["bigram_log_likelihood_2"],
            features["bigram_log_likelihood_3"],
            features["consonant_vowel_ratio"],
            features["digit_ratio"],
            features["domain_length"],
            features["tld_length"],
            1 if features["has_dictionary_word"] else 0,
        ])
    X = np.array(X_benign + X_malicious, dtype=float)
    y = np.array([0] * len(X_benign) + [1] * len(X_malicious))
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    train_data = lgb.Dataset(X_train, label=y_train)
    test_data = lgb.Dataset(X_test, label=y_test, reference=train_data)
    params = {"objective": "binary","metric": "auc","boosting_type": "gbdt","learning_rate": 0.1,"num_leaves": 31,"feature_fraction": 0.8,"bagging_fraction": 0.8,"bagging_freq": 5,"verbosity": -1}
    clf = lgb.train(params, train_data, num_boost_round=100, valid_sets=[train_data, test_data], callbacks=[lgb.early_stopping(10), lgb.log_evaluation(0)])
    train_pred = clf.predict(X_train)
    test_pred = clf.predict(X_test)
    from sklearn.metrics import roc_auc_score, confusion_matrix
    train_auc = roc_auc_score(y_train, train_pred)
    test_auc = roc_auc_score(y_test, test_pred)
    test_pred_class = (test_pred > 0.5).astype(int)
    cm = confusion_matrix(y_test, test_pred_class)
    tn, fp, fn, tp = cm.ravel() if cm.size == 4 else (0, 0, 0, 0)
    import os, joblib
    os.makedirs(output_dir, exist_ok=True)
    model_path = os.path.join(output_dir, "dga_classifier.joblib")
    joblib.dump(clf, model_path)
    print(f"DGA training complete: Train AUC={train_auc:.4f} Test AUC={test_auc:.4f} CM TN={tn} FP={fp} FN={fn} TP={tp} saved to {model_path}")
    return clf, train_auc, test_auc


def predict_dga(model: Any, domain: str) -> dict:
    if not LIGHTGBM_AVAILABLE:
        raise ImportError("LightGBM not available")
    features = extract_dga_domain_features(domain)
    feature_vector = np.array([[
        features["domain_entropy"],
        features["bigram_log_likelihood_2"],
        features["bigram_log_likelihood_3"],
        features["consonant_vowel_ratio"],
        features["digit_ratio"],
        features["domain_length"],
        features["tld_length"],
        1 if features["has_dictionary_word"] else 0,
    ]], dtype=float)
    prob = float(model.predict(feature_vector)[0])
    prediction = int(prob > 0.5)
    return {"domain": domain,"is_dga": bool(prediction),"dga_probability": prob,"confidence": max(prob, 1 - prob),"features": features}
