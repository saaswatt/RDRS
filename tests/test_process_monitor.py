
import os

import pytest

import psutil

from app.collectors.process_monitor import inspect_process

from app.collectors import process_monitor

from contextlib import nullcontext
from types import SimpleNamespace
from unittest.mock import MagicMock
from app.collectors.process_monitor import collect_running_processes

def test_inspect_current_process():
    """
    Verify that the current Python process
    can be inspected successfully.
    """

    result = inspect_process(os.getpid())

    assert result is not None
    assert result["pid"] == os.getpid()
    assert result["name"] is not None
    assert result["timestamp"] is not None
    assert result["status"] is not None

    assert isinstance(result["memory_rss"], int)
    assert result["memory_rss"] >= 0


@pytest.mark.parametrize(
    "invalid_pid",
    [0, -1, True, "1234", 1.5]
)
def test_inspect_process_rejects_invalid_pid(invalid_pid):
    """
    Verify that invalid PID values are rejected.
    """

    with pytest.raises(ValueError):
        inspect_process(invalid_pid)


def test_inspect_process_handles_disappeared_process(monkeypatch):
    """
    Verify that a process disappearing during inspection
    does not crash the collector.
    """

    def fake_process(pid):
        raise psutil.NoSuchProcess(pid)

    monkeypatch.setattr(
        process_monitor.psutil,
        "Process",
        fake_process
    )

    result = inspect_process(999999)

    assert result is None

def test_inspect_process_handles_access_denied(monkeypatch):
    """
    Verify that access-denied errors do not crash
    the process collector.
    """

    def fake_process(pid):
        raise psutil.AccessDenied(pid)

    monkeypatch.setattr(
        process_monitor.psutil,
        "Process",
        fake_process
    )

    result = inspect_process(1000)

    assert result is None


def test_inspect_process_handles_unavailable_disk_io(monkeypatch):
    """
    Verify that unavailable disk I/O information
    does not prevent process metadata collection.
    """

    fake_process = MagicMock()

    fake_process.oneshot.return_value = nullcontext()

    fake_process.as_dict.return_value = {
        "pid": 1234,
        "name": "test.exe",
        "exe": "C:\\test.exe",
        "ppid": 100,
        "create_time": 1793800000.0,
        "cpu_percent": 2.5,
        "memory_percent": 1.5,
        "memory_info": SimpleNamespace(rss=1024000),
        "username": "TEST_USER",
        "status": "running"
    }

    fake_process.io_counters.side_effect = psutil.AccessDenied(1234)

    monkeypatch.setattr(
        process_monitor.psutil,
        "Process",
        lambda pid: fake_process
    )

    result = inspect_process(1234)

    assert result is not None
    assert result["pid"] == 1234
    assert result["memory_rss"] == 1024000
    assert result["disk_read_bytes"] is None
    assert result["disk_write_bytes"] is None


def test_collect_running_processes(monkeypatch):
    """
    Verify that the collector gathers accessible
    process metadata and skips unavailable processes.
    """

    fake_processes = [
        {"pid": 101, "name": "process1.exe"},
        None,
        {"pid": 103, "name": "process3.exe"}
    ]

    monkeypatch.setattr(
        process_monitor.psutil,
        "pids",
        lambda: [101, 102, 103]
    )

    monkeypatch.setattr(
        process_monitor,
        "inspect_process",
        lambda pid: fake_processes[pid - 101]
    )

    result = collect_running_processes()

    assert len(result) == 2
    assert result[0]["pid"] == 101
    assert result[1]["pid"] == 103
def test_collect_running_processes_handles_enumeration_failure(monkeypatch):
    """
    Verify that process enumeration failures
    do not crash the collector.
    """

    def fake_pids():
        raise psutil.AccessDenied()

    monkeypatch.setattr(
        process_monitor.psutil,
        "pids",
        fake_pids
    )

    result = collect_running_processes()

    assert result == []
def test_collect_running_processes_skips_invalid_pids(monkeypatch):
    """
    Verify that invalid PIDs returned by the operating
    system are skipped before individual inspection.
    """

    inspected_pids = []

    def fake_inspect_process(pid):
        inspected_pids.append(pid)
        return {"pid": pid, "name": "test.exe"}

    monkeypatch.setattr(
        process_monitor.psutil,
        "pids",
        lambda: [0, 101, -1, 102]
    )

    monkeypatch.setattr(
        process_monitor,
        "inspect_process",
        fake_inspect_process
    )

    result = collect_running_processes()

    assert len(result) == 2
    assert inspected_pids == [101, 102]
    assert [process["pid"] for process in result] == [101, 102]