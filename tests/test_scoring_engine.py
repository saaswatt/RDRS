
import pytest

from app.core.config import load_config
from app.detectors.scoring_engine import (
    calculate_threat_score,
    get_threat_level,
)


@pytest.fixture
def config():
    return load_config()


def test_calculates_weighted_threat_score(config):
    signals = {
        "rapid_modification": True,
        "mass_rename": True,
        "high_entropy": True,
        "cpu_spike": False,
        "unknown_program": False,
    }

    result = calculate_threat_score(signals, config)

    assert result["raw_score"] == 95
    assert result["threat_score"] == 95
    assert result["threat_level"] == "CRITICAL"


def test_caps_threat_score_at_100(config):
    signals = {
        "rapid_modification": True,
        "mass_rename": True,
        "high_entropy": True,
        "cpu_spike": True,
        "unknown_program": True,
    }

    result = calculate_threat_score(signals, config)

    assert result["raw_score"] == 120
    assert result["threat_score"] == 100
    assert result["threat_level"] == "CRITICAL"


@pytest.mark.parametrize(
    ("score", "expected_level"),
    [
        (0, "NORMAL"),
        (40, "NORMAL"),
        (41, "WARNING"),
        (70, "WARNING"),
        (71, "CRITICAL"),
        (100, "CRITICAL"),
    ],
)
def test_threat_level_boundaries(score, expected_level):
    assert get_threat_level(score) == expected_level


def test_missing_signals_default_to_false(config):
    result = calculate_threat_score({}, config)

    assert result["threat_score"] == 0
    assert result["threat_level"] == "NORMAL"
    assert result["triggered_signals"] == []


def test_score_breakdown_contains_triggered_weights(config):
    signals = {
        "rapid_modification": True,
        "mass_rename": False,
        "high_entropy": True,
    }

    result = calculate_threat_score(signals, config)

    assert result["score_breakdown"] == {
        "rapid_modification": 40,
        "high_entropy": 25,
    }


def test_rejects_unsupported_signal(config):
    with pytest.raises(ValueError, match="Unsupported detection signals"):
        calculate_threat_score({"unknown_signal": True}, config)


def test_rejects_non_boolean_signal_values(config):
    with pytest.raises(ValueError, match="must have a boolean value"):
        calculate_threat_score({"rapid_modification": 1}, config)


def test_rejects_invalid_threat_scores():
    with pytest.raises(ValueError):
        get_threat_level(-1)

    with pytest.raises(ValueError):
        get_threat_level(101)

    with pytest.raises(ValueError):
        get_threat_level(True)
