from __future__ import annotations

import math
import numpy as np
from typing import Dict, List, Any, Optional

from scipy import stats
from scipy.fft import fft

from app.config import settings


def compute_inter_arrival_times(pkt_timestamps: List[float]) -> List[float]:
    """Compute inter-arrival times between consecutive packets.

    Args:
        pkt_timestamps: Sorted list of packet timestamps

    Returns:
        List of inter-arrival durations in seconds
    """
    if len(pkt_timestamps) < 2:
        return []
    arrival_times = []
    for i in range(1, len(pkt_timestamps)):
        arrival_times.append(pkt_timestamps[i] - pkt_timestamps[i - 1])
    return arrival_times


def compute_coefficient_of_variation(values: List[float]) -> float:
    """Compute coefficient of variation (std/mean).

    A CV < 0.1 indicates highly periodic (beacon-like) timing.
    """
    if not values or len(values) < 2:
        return 1.0  # High uncertainty = not periodic
    mean_val = np.mean(values)
    if mean_val == 0:
        return 1.0
    std_val = np.std(values, ddof=1)
    if std_val == 0:
        return 0.0
    return float(std_val / mean_val)


def compute_fft_periodicity(pkt_timestamps: List[float], sample_rate: float = 1.0) -> dict:
    """Compute FFT-based periodicity analysis.

    Finds the dominant frequency in packet inter-arrival times.
    Returns the dominant frequency and power score.

    Args:
        pkt_timestamps: Sorted list of packet timestamps
        sample_rate: Approximate sampling rate (packets/sec)

    Returns:
        Dict with dominant_freq, periodicity_score, dominant_period
    """
    arrival_times = compute_inter_arrival_times(pkt_timestamps)

    if len(arrival_times) < 4:
        return {
            "dominant_freq": 0.0,
            "periodicity_score": 0.0,
            "dominant_period": 0.0,
            "fft_power": 0.0,
        }

    # Compute FFT
    arrival_array = np.array(arrival_times, dtype=float)
    # Remove any non-positive values
    arrival_array = arrival_array[arrival_array > 0]

    if len(arrival_array) < 4:
        return {
            "dominant_freq": 0.0,
            "periodicity_score": 0.0,
            "dominant_period": 0.0,
            "fft_power": 0.0,
        }

    fft_result = fft(arrival_array)
    magnitudes = np.abs(fft_result[:len(fft_result) // 2])
    powers = magnitudes ** 2

    # Find dominant frequency index (excluding DC component at index 0)
    if len(powers) > 1:
        dominant_idx = np.argmax(powers[1:]) + 1  # Skip DC
        dominant_freq = float(dominant_idx * sample_rate / len(arrival_array))
        dominant_power = float(powers[dominant_idx])
    else:
        dominant_freq = 0.0
        dominant_power = 0.0

    # Periodicity score: normalized power at dominant frequency
    total_power = np.sum(powers)
    if total_power > 0:
        periodicity_score = dominant_power / total_power
    else:
        periodicity_score = 0.0

    # Dominant period = 1 / dominant_freq (if freq > 0)
    dominant_period = 1.0 / dominant_freq if dominant_freq > 0 else 0.0

    return {
        "dominant_freq": dominant_freq,
        "periodicity_score": float(periodicity_score),
        "dominant_period": dominant_period,
        "fft_power": dominant_power,
    }


def compute_jitter(pkt_timestamps: List[float]) -> float:
    """Compute jitter = variation in inter-arrival times.

    High jitter = irregular traffic (less likely beacon).
    Low jitter = consistent intervals (more like beacon).
    """
    arrival_times = compute_inter_arrival_times(pkt_timestamps)

    if len(arrival_times) < 2:
        return 1.0  # High uncertainty

    # Mean deviation from mean inter-arrival
    if not arrival_times:
        return 1.0

    mean_arrival = np.mean(arrival_times)
    if mean_arrival == 0:
        return 1.0

    deviations = [abs(t - mean_arrival) for t in arrival_times]
    jitter = float(np.mean(deviations)) / mean_arrival
    return jitter


def compute_destination_rarity(dst_ip: str, flow_table: Any) -> float:
    """Estimate how rare a destination IP is in the overall flow table.

    Rare destinations (e.g., C2 servers) get higher rarity score.
    Common destinations (e.g., google.com) get low rarity.

    Args:
        dst_ip: Destination IP address
        flow_table: FlowTable instance for context

    Returns:
        Rarity score in range [0, 1], higher = rarer
    """
    # Simple heuristic: if destination appears in few flows, it's rarer
    # In production, this would query a global flow table / Redis
    # For MVP, use inverse frequency
    return 0.5  # placeholder


def extract_beacon_features(flow: FlowState) -> dict:
    """Extract all C2 beacon features from a flow.

    Features for beacon detection using FFT + timing analysis.

    Read-only: only analyzes observed packet timing metadata.
    """
    timestamps = flow.timestamps
    pkt_count = flow.packet_count

    if len(timestamps) < settings.beacon_min_observations:
        return {
            "inter_arrival_cv": 1.0,
            "periodicity_score": 0.0,
            "dominant_period": 0.0,
            "jitter": 1.0,
            "destination_rarity": 0.5,
            "timing_consistency": 0.0,
            "observation_count": len(timestamps),
            "is_sufficient_observations": False,
        }

    # Compute inter-arrival CV
    arrival_times = compute_inter_arrival_times(timestamps)
    cv = compute_coefficient_of_variation(arrival_times) if arrival_times else 1.0

    # FFT periodicity analysis
    # Estimate sample rate from flow duration
    dur = flow.duration_seconds()
    sample_rate = float(pkt_count) / max(dur, 1.0)

    fft_result = compute_fft_periodicity(timestamps, sample_rate=sample_rate)

    # Destination rarity (needs flow table context)
    rarity = compute_destination_rarity(flow.dst_ip, flow)

    # Timing consistency: inverse of CV (lower CV = more consistent)
    timing_consistency = 1.0 - min(cv, 1.0)

    features = {
        "inter_arrival_cv": cv,
        "periodicity_score": fft_result["periodicity_score"],
        "dominant_period": fft_result["dominant_period"],
        "jitter": compute_jitter(timestamps),
        "destination_rarity": rarity,
        "timing_consistency": timing_consistency,
        "observation_count": len(timestamps),
        "is_sufficient_observations": len(timestamps) >= settings.beacon_min_observations,
    }

    return features