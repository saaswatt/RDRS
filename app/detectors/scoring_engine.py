
from collections.abc import Mapping
from typing import Any

from app.core.config import RDRSConfig


# Maps detection-engine signal names to configuration scoring weights.
SIGNAL_WEIGHT_MAP = {
    "rapid_modification": "rapid_encryption",
    "mass_rename": "mass_rename",
    "high_entropy": "high_entropy",
    "cpu_spike": "cpu_spike",
    "unknown_program": "unknown_program",
}


def get_threat_level(threat_score: int) -> str:
    """
    Convert a threat score into a severity level.

    Agreed boundaries:
    Normal:   0–40
    Warning: 41–70
    Critical: 71–100
    """
    if isinstance(threat_score, bool) or not isinstance(threat_score, int):
        raise ValueError("Threat score must be an integer.")

    if not 0 <= threat_score <= 100:
        raise ValueError("Threat score must be between 0 and 100.")

    if threat_score <= 40:
        return "NORMAL"

    if threat_score <= 70:
        return "WARNING"

    return "CRITICAL"


def calculate_threat_score(
    signals: Mapping[str, Any],
    config: RDRSConfig,
) -> dict[str, Any]:
    """
    Calculate a weighted threat score from detection signals.

    Each active signal contributes its configured weight.
    The final score is capped at 100.

    The function does not perform database operations or
    incident response actions.
    """
    if not isinstance(signals, Mapping):
        raise TypeError("Signals must be provided as a mapping.")

    if not isinstance(config, RDRSConfig):
        raise TypeError("Config must be an RDRSConfig instance.")

    unknown_signals = set(signals) - set(SIGNAL_WEIGHT_MAP)

    if unknown_signals:
        raise ValueError(
            f"Unsupported detection signals: {sorted(unknown_signals)}"
        )

    raw_score = 0
    triggered_signals = []
    score_breakdown = {}

    for signal_name, weight_name in SIGNAL_WEIGHT_MAP.items():
        is_triggered = signals.get(signal_name, False)

        if not isinstance(is_triggered, bool):
            raise ValueError(
                f"Signal '{signal_name}' must have a boolean value."
            )

        if is_triggered:
            weight = getattr(config.scoring, weight_name)

            raw_score += weight
            triggered_signals.append(signal_name)
            score_breakdown[signal_name] = weight

    threat_score = min(raw_score, 100)
    threat_level = get_threat_level(threat_score)

    return {
        "raw_score": raw_score,
        "threat_score": threat_score,
        "threat_level": threat_level,
        "triggered_signals": triggered_signals,
        "score_breakdown": score_breakdown,
    }
