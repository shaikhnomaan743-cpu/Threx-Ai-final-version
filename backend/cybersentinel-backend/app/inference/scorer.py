from __future__ import annotations

import numpy as np
from typing import Dict, List, Any

from app.alerts.schema import Evidence


class EvidenceScorer:
    """Scores and ranks evidence features for alert explanations.

    Computes contribution scores and generates human-readable explanations
    for why an alert was raised.
    """

    @staticmethod
    def rank_by_contribution(evidence: List[Evidence]) -> List[Evidence]:
        """Rank evidence features by their contribution score (descending)."""
        if not evidence:
            return evidence
        return sorted(evidence, key=lambda e: e.contribution, reverse=True)

    @staticmethod
    def generate_explanation(alert: Any) -> str:
        """Generate a human-readable explanation for an alert.

        Args:
            alert: Alert Pydantic model instance

        Returns:
            String explaining the detection rationale
        """
        if not alert.evidence:
            return "Alert raised by detection system"

        # Rank evidence by contribution
        ranked = EvidenceScorer.rank_by_contribution(alert.evidence)

        # Build explanation
        parts = []
        for ev in ranked[:3]:  # Top 3 features
            parts.append(f"{ev.description}")

        if not parts:
            return "Alert raised by detection system"

        explanation = ". ".join(parts) + "."
        return explanation

    @staticmethod
    def contribution_summary(alert: Any) -> Dict[str, float]:
        """Get a summary of evidence contributions as a dict.

        Returns dict mapping feature_name -> contribution score.
        """
        if not alert.evidence:
            return {}

        return {
            ev.feature_name: round(ev.contribution, 2)
            for ev in alert.evidence
        }


class Scorer:
    """Combines rule-based + ML scores into final confidence.

    The final confidence is a weighted combination:
    - Rule-based thresholds: 40% weight
    - ML model scores: 60% weight

    This ensures that even without ML models, rule-based detection
    works reliably, while ML enhances detection accuracy.
    """

    @staticmethod
    def combine_confidence(
        rule_score: float,
        ml_score: float,
        rule_weight: float = 0.4,
        ml_weight: float = 0.6,
    ) -> float:
        """Combine rule and ML confidence scores.

        Args:
            rule_score: Rule-based confidence (0-1), e.g., from threshold checks
            ml_score: ML model confidence (0-1), e.g., from Isolation Forest or RF
            rule_weight: Weight for rule-based score (default 0.4)
            ml_weight: Weight for ML score (default 0.6)

        Returns:
            Combined confidence in [0, 1]
        """
        # Normalize weights
        total_weight = rule_weight + ml_weight
        normalized_rule = rule_weight / total_weight
        normalized_ml = ml_weight / total_weight

        combined = (normalized_rule * rule_score +
                    normalized_ml * ml_score)
        return round(min(max(combined, 0.0), 1.0), 4)

    @staticmethod
    def determine_severity(confidence: float, threat_class: str) -> str:
        """Determine severity level from confidence and threat class.

        Uses different thresholds per threat type for fine-grained control.
        """
        # Base thresholds on confidence
        if confidence >= 0.8:
            base_severity = "critical"
        elif confidence >= 0.6:
            base_severity = "high"
        elif confidence >= 0.4:
            base_severity = "medium"
        else:
            base_severity = "low"

        # Adjust per threat class
        threat_adjustments = {
            "ddos": {
                "critical": 0.75,  # Lower bar for critical
                "high": 0.55,
            },
            "c2_beacon": {
                "critical": 0.65,
                "high": 0.45,
            },
            "exfiltration": {
                "critical": 0.7,
                "high": 0.5,
            },
            "tls_malware": {
                "critical": 0.7,
                "high": 0.5,
            },
            "port_scan": {
                "high": 0.6,
                "medium": 0.4,
            },
        }

        adjustments = threat_adjustments.get(threat_class, {})

        # If confidence meets adjusted threshold, use that severity
        for sev_level, threshold in sorted(adjustments.items(), key=lambda x: -x[1]):
            if confidence >= threshold:
                return sev_level

        return base_severity