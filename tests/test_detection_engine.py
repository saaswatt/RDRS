
import pytest

from app.core.config import load_config
from app.detectors.detection_engine import analyze_filesystem_events


@pytest.fixture
def config():
    return load_config()


def make_event(
    event_type,
    source_path="data/sandbox/test.txt",
    destination_path=None,
    entropy=None,
):
    return {
        "event_type": event_type,
        "source_path": source_path,
        "destination_path": destination_path,
        "entropy": entropy,
    }


def test_empty_event_list_returns_zero_counts_and_no_signals(config):
    result = analyze_filesystem_events([], config)

    assert result["event_count"] == 0
    assert result["modified_count"] == 0
    assert result["rename_count"] == 0
    assert result["extension_change_count"] == 0
    assert result["average_entropy"] is None

    assert result["signals"] == {
        "rapid_modification": False,
        "mass_rename": False,
        "high_entropy": False,
    }


def test_rapid_modification_signal_triggers_at_threshold(config):
    threshold = config.detection.thresholds.rapid_modification

    events = [
        make_event("MODIFIED")
        for _ in range(threshold)
    ]

    result = analyze_filesystem_events(events, config)

    assert result["modified_count"] == threshold
    assert result["signals"]["rapid_modification"] is True


def test_mass_rename_signal_triggers_at_threshold(config):
    threshold = config.detection.thresholds.mass_rename

    events = [
        make_event(
            "MOVED",
            source_path=f"data/sandbox/file_{i}.txt",
            destination_path=f"data/sandbox/file_{i}.locked",
        )
        for i in range(threshold)
    ]

    result = analyze_filesystem_events(events, config)

    assert result["rename_count"] == threshold
    assert result["signals"]["mass_rename"] is True


def test_extension_changes_are_counted(config):
    events = [
        make_event(
            "MOVED",
            source_path="data/sandbox/document.docx",
            destination_path="data/sandbox/document.locked",
        ),
        make_event(
            "MOVED",
            source_path="data/sandbox/image.png",
            destination_path="data/sandbox/image.locked",
        ),
        make_event(
            "MOVED",
            source_path="data/sandbox/notes.txt",
            destination_path="data/sandbox/notes.txt",
        ),
    ]

    result = analyze_filesystem_events(events, config)

    assert result["extension_change_count"] == 2


def test_high_entropy_signal_uses_average_available_entropy(config):
    threshold = config.detection.thresholds.high_entropy

    events = [
        make_event("CREATED", entropy=threshold),
        make_event("MODIFIED", entropy=threshold),
    ]

    result = analyze_filesystem_events(events, config)

    assert result["average_entropy"] == pytest.approx(threshold)
    assert result["signals"]["high_entropy"] is True


def test_missing_entropy_values_are_ignored(config):
    events = [
        make_event("CREATED", entropy=7.5),
        make_event("MODIFIED", entropy=None),
        make_event("MODIFIED", entropy=6.5),
    ]

    result = analyze_filesystem_events(events, config)

    assert result["average_entropy"] == pytest.approx(7.0)
