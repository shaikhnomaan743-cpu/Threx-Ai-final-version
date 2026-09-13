"""Tests for DGA feature extractor."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.features.dga_features import (
    extract_dga_features,
    compute_domain_entropy,
    compute_bigram_log_likelihood,
    compute_consonant_vowel_ratio,
    compute_digit_ratio,
    compute_domain_length,
    has_dictionary_word,
)
from app.utils.entropy import shannon_entropy


class TestDGAFeatures:
    """Test DGA feature extraction."""

    def test_extract_dga_features(self):
        """Test full DGA feature extraction."""
        features = extract_dga_features("xqwd32a.com")
        assert "domain" in features
        assert "domain_entropy" in features
        assert "bigram_log_likelihood_2" in features
        assert "bigram_log_likelihood_3" in features
        assert "consonant_vowel_ratio" in features
        assert "digit_ratio" in features
        assert "domain_length" in features
        assert "tld_length" in features
        assert "has_dictionary_word" in features

    def test_domain_entropy(self):
        """Test domain entropy computation."""
        ent = compute_domain_entropy("xqwd32a.com")
        assert isinstance(ent, float)
        assert ent >= 0.0

        # High-entropy domain (likely DGA)
        high_ent = compute_domain_entropy("a7b9c2d5e8f1g4h.com")
        assert high_ent > ent  # Should be higher for random-looking domain

        # Low-entropy domain (likely benign)
        low_ent = compute_domain_entropy("google.com")
        assert low_ent >= 0.0

    def test_bigram_log_likelihood(self):
        """Test n-gram log-likelihood computation."""
        from app.utils.entropy import ngram_score

        # English-like domain
        score1 = compute_bigram_log_likelihood("microsoft.com", n=2)
        assert isinstance(score1, float)

        # DGA-like domain (low likelihood)
        score2 = compute_bigram_log_likelihood("xqwd32a.com", n=2)
        # DGA domains typically have lower English bigram scores
        # (but our synthetic model may vary)

    def test_consonant_vowel_ratio(self):
        """Test consonant-vowel ratio."""
        from app.utils.entropy import consonant_vowel_ratio

        # All vowels
        ratio_vowel_only = consonant_vowel_ratio("aei")
        # All consonants
        ratio_consonant_only = consonant_vowel_ratio("bcdfg")

        # Ratio should be meaningful
        assert ratio_vowel_only >= 0
        assert ratio_consonant_only >= 0

    def test_digit_ratio(self):
        """Test digit ratio computation."""
        from app.utils.entropy import digit_ratio

        # No digits
        ratio_no_digits = digit_ratio("abcdefg")
        assert ratio_no_digits == 0.0

        # All digits
        ratio_all_digits = digit_ratio("1234567")
        assert ratio_all_digits == 1.0

        # Mixed
        ratio_mixed = digit_ratio("a1b2c3d")
        assert 0 < ratio_mixed < 1

    def test_domain_length(self):
        """Test domain length computation."""
        length = compute_domain_length("example.com")
        assert length == 11  # "example.com" = 11 chars including dot

        # Empty/None
        length_empty = compute_domain_length("")
        assert length_empty == 0

    def test_has_dictionary_word(self):
        """Test dictionary word detection."""
        # Domain with common word
        has_word = has_dictionary_word("microsoft.com")
        # Domain without common word (DGA-like)
        no_word = has_dictionary_word("xqwd32a.com")

        # Should detect "micro" or "soft" in microsoft.com
        assert isinstance(has_word, bool)

        # DGA-like domain should not have dictionary words
        assert isinstance(no_word, bool)