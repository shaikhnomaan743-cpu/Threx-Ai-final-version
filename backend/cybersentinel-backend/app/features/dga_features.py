from __future__ import annotations

import numpy as np
from typing import Dict, List, Any, Optional

from app.utils.entropy import shannon_entropy, ngram_score, consonant_vowel_ratio, digit_ratio


def compute_domain_entropy(domain: str) -> float:
    """Compute Shannon entropy of a domain name's characters.

    High entropy (>4.0) suggests algorithmically generated domains (DGAs).
    Low entropy suggests human-readable or dictionary-based domains.
    """
    if not domain:
        return 0.0
    # Clean the domain
    domain = domain.lower().strip(".")
    ent = shannon_entropy(domain.encode("utf-8"))
    return ent


def compute_bigram_log_likelihood(domain: str, n: int = 2) -> float:
    """Compute bigram/trigram log-likelihood score.

    Uses English n-gram model from utils. Higher score = more English-like.
    DGAs typically have low n-gram scores (non-random but not English).
    """
    domain = domain.lower().strip(".")
    score = ngram_score(domain, n=n, use_log=True)
    return score


def compute_consonant_vowel_ratio(domain: str) -> float:
    """Compute consonant-to-vowel ratio in domain name."""
    return consonant_vowel_ratio(domain)


def compute_digit_ratio(domain: str) -> float:
    """Compute ratio of digits to total alphanumeric characters."""
    return digit_ratio(domain)


def compute_domain_length(domain: str) -> int:
    """Compute length of domain name (excluding dots)."""
    if not domain:
        return 0
    return len(domain.strip("."))


def has_dictionary_word(domain: str, dictionary: Optional[set] = None) -> bool:
    """Check if domain contains a known dictionary word.

    DGAs typically avoid real words. This checks substring matches
    against a small built-in set; a full implementation would use
    a word list like /usr/share/dict/words.
    """
    if dictionary is None:
        # Small built-in set for MVP demo
        dictionary = {"account", "update", "verify", "login", "secure",
                      "confirm", "server", "client", "host", "network"}
    else:
        dictionary = set(domain.lower().strip(".").split("."))

    domain_lower = domain.lower().strip(".")
    # Check for common dictionary substrings
    for word in dictionary:
        if word in domain_lower and len(word) >= 3:
            return True
    return False


def compute_tld_length(domain: str) -> int:
    """Compute TLD (top-level domain) length."""
    if not domain:
        return 0
    parts = domain.lower().split(".")
    if parts:
        return len(parts[-1])
    return 0


def extract_dga_features(domain: str) -> dict:
    """Extract all DGA classification features from a domain name.

    Features used by the LightGBM classifier.

    Read-only: only analyzes domain string metadata.
    """
    features = {
        "domain": domain.lower().strip("."),
        "domain_entropy": compute_domain_entropy(domain),
        "bigram_log_likelihood_2": compute_bigram_log_likelihood(domain, n=2),
        "bigram_log_likelihood_3": compute_bigram_log_likelihood(domain, n=3),
        "consonant_vowel_ratio": compute_consonant_vowel_ratio(domain),
        "digit_ratio": compute_digit_ratio(domain),
        "domain_length": compute_domain_length(domain),
        "tld_length": compute_tld_length(domain),
        "has_dictionary_word": has_dictionary_word(domain),
        "vowel_count": sum(1 for c in domain.lower() if c in "aeiou"),
        "consonant_count": sum(1 for c in domain.lower() if c not in "aeiou" and c.isalpha()),
    }

    return features