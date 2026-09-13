import math


def shannon_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of bytes data."""
    if not data:
        return 0.0
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    length = len(data)
    entropy = 0.0
    for count in freq.values():
        p = count / length
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def shannon_entropy_float(freq_dict: dict) -> float:
    """Calculate Shannon entropy from a frequency dict {value: count}."""
    total = sum(freq_dict.values())
    if total == 0:
        return 0.0
    entropy = 0.0
    for count in freq_dict.values():
        p = count / total
        if p > 0:
            entropy -= p * math.log2(p)
    return entropy


def consonant_vowel_ratio(domain: str) -> float:
    """Calculate ratio of consonants to vowels in a domain string."""
    domain = domain.lower().strip(".")
    vowels = set("aeiou")
    consonants = 0
    vowels_count = 0
    for ch in domain:
        if ch.isalpha():
            if ch in vowels:
                vowels_count += 1
            else:
                consonants += 1
    if vowels_count == 0:
        return float(consonants)
    return consonants / vowels_count


def digit_ratio(domain: str) -> float:
    """Calculate ratio of digits to total alphanumeric characters in a domain."""
    domain = domain.lower().strip(".")
    total = 0
    digits = 0
    for ch in domain:
        if ch.isalnum():
            total += 1
            if ch.isdigit():
                digits += 1
    if total == 0:
        return 0.0
    return digits / total


def ngram_score(text: str, n: int = 2, use_log: bool = True) -> float:
    """Calculate n-gram log-likelihood score for text.

    Uses a pre-computed English corpus model. If use_log is True,
    returns log-probability; otherwise returns raw probability.
    """
    # Common bigram/trigram frequencies from English text
    # In a full implementation, these would be loaded from trained models
    english_bigrams = {
        "th": 0.0317, "he": 0.0306, "in": 0.0241, "er": 0.0188,
        "an": 0.0166, "re": 0.0161, "on": 0.0143, "at": 0.0131,
        "en": 0.0125, "ed": 0.0120, "es": 0.0108, "st": 0.0105,
        "or": 0.0099, "ti": 0.0097, "al": 0.0095, "si": 0.0093,
        "te": 0.0089, "se": 0.0087, "de": 0.0085, "to": 0.0083,
        "at": 0.0081, "hi": 0.0078, "ou": 0.0076, "en": 0.0074,
        "ed": 0.0072, "ing": 0.0069, "c": 0.0068, "ion": 0.0066,
        "of": 0.0064, "a": 0.0651, "o": 0.0798, "i": 0.0731,
        "n": 0.0695, "s": 0.0633, "t": 0.0468, "r": 0.0497,
        "h": 0.0344, "d": 0.0306, "l": 0.0350, "u": 0.0226,
        "m": 0.0241, "w": 0.0236, "c": 0.0236, "y": 0.0211,
        "f": 0.0186, "g": 0.0174, "p": 0.0192, "b": 0.0149,
        "v": 0.0088, "k": 0.0067, "x": 0.0011, "q": 0.0009,
        "z": 0.0007,
    }

    if len(text) < n:
        return 0.0

    score = 0.0
    text = text.lower()
    for i in range(len(text) - n + 1):
        ngram = text[i:i + n]
        if ngram in english_bigrams:
            p = english_bigrams[ngram]
            if use_log:
                score += math.log(p) if p > 0 else float("-inf")
            else:
                score += p
        else:
            # Unknown ngram - assign small probability
            if use_log:
                score += math.log(1e-10)
            else:
                score += 1e-10
    return score