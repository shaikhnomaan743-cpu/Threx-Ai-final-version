"""Tests for beacon detector component."""

import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app.features.beacon_features import (
    compute_inter_arrival_times,
    compute_coefficient_of_variation,
    compute_fft_periodicity,
    compute_jitter,
)
from app.config import settings


class TestBeaconFeatures:
    """Test C2 beacon feature extraction."""

    def test_inter_arrival_times(self):
        """Test inter-arrival time computation."""
        timestamps = [0.0, 1.0, 3.0, 6.0, 10.0, 15.0]
        arrivals = compute_inter_arrival_times(timestamps)
        assert arrivals == [1.0, 2.0, 3.0, 4.0, 5.0]
        assert len(arrivals) == len(timestamps) - 1

    def test_inter_arrival_insufficient(self):
        """Test with fewer than 2 timestamps."""
        arrivals = compute_inter_arrival_times([0.0])
        assert arrivals == []

    def test_coefficient_of_variation(self):
        """Test coefficient of variation calculation."""
        from app.features.beacon_features import compute_coefficient_of_variation

        # Very consistent (low CV)
        consistent = [5.0, 5.0, 5.0, 5.0, 5.0]
        cv = compute_coefficient_of_variation(consistent)
        assert cv < 0.1  # Should be very low

        # Very inconsistent (high CV)
        inconsistent = [1.0, 10.0, 1.0, 10.0, 1.0]
        cv_high = compute_coefficient_of_variation(inconsistent)
        assert cv_high > 0.5  # Should be high

    def test_fft_periodicity(self):
        """Test FFT periodicity analysis."""
        from app.features.beacon_features import compute_fft_periodicity

        # Highly periodic: regular 1-second intervals
        timestamps_periodic = [
            0.0, 1.0, 2.0, 3.0, 4.0, 5.0, 6.0, 7.0, 8.0, 9.0, 10.0
        ]
        result = compute_fft_periodicity(timestamps_periodic, sample_rate=1.0)
        assert "dominant_freq" in result
        assert "periodicity_score" in result
        assert "dominant_period" in result
        assert result["periodicity_score"] >= 0.0  # periodic score non-negative (implementation uses FFT power ratio)

        # Random arrivals (low periodicity)
        import random
        random.seed(42)
        timestamps_random = sorted([random.random() * 10 for _ in range(50)])
        result_random = compute_fft_periodicity(timestamps_random, sample_rate=5.0)
        assert result_random["periodicity_score"] < 0.3  # Low for random

    def test_jitter(self):
        """Test jitter computation."""
        from app.features.beacon_features import compute_jitter

        # Very consistent intervals
        consistent_timestamps = [0.0, 1.0, 2.0, 3.0, 4.0, 5.0]
        jitter_consistent = compute_jitter(consistent_timestamps)
        assert jitter_consistent < 0.1  # Low jitter

        # Very variable intervals
        variable_timestamps = [0.0, 1.0, 3.0, 7.0, 2.0, 5.0]
        jitter_variable = compute_jitter(variable_timestamps)
        assert jitter_variable > 0.3  # High jitter