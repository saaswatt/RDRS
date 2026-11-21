
"""
RDRS Process Monitoring Module.

Collects process metadata using psutil.
"""

from datetime import datetime, timezone
from typing import Any

import psutil

from app.core.logging import get_logger


system_logger = get_logger("system")
error_logger = get_logger("errors")


# Retain Process objects between collection cycles so that
# psutil can calculate CPU usage using successive measurements.
_PROCESS_CACHE: dict[int, tuple[float, psutil.Process]] = {}


def inspect_process(pid: int) -> dict[str, Any] | None:
    """
    Collect metadata for a specific running process.

    Returns:
        A dictionary containing process metadata,
        or None if the process is unavailable.
    """

    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        raise ValueError("PID must be a positive integer.")

    try:
        cached_entry = _PROCESS_CACHE.get(pid)
        process = None

        if cached_entry is not None:
            cached_create_time, cached_process = cached_entry

            try:
                if (
                    cached_process.is_running()
                    and cached_process.create_time() == cached_create_time
                ):
                    process = cached_process

            except psutil.Error:
                process = None

        if process is None:
            process = psutil.Process(pid)
            process_create_time = process.create_time()

            _PROCESS_CACHE[pid] = (
                process_create_time,
                process
            )

        with process.oneshot():

            info = process.as_dict(
                attrs=[
                    "pid",
                    "name",
                    "exe",
                    "ppid",
                    "create_time",
                    "cpu_percent",
                    "memory_percent",
                    "memory_info",
                    "username",
                    "status"
                ],
                ad_value=None
            )

            memory_info = info.get("memory_info")

            try:
                disk_io = process.io_counters()

                disk_read_bytes = disk_io.read_bytes
                disk_write_bytes = disk_io.write_bytes

            except (
                psutil.AccessDenied,
                psutil.ZombieProcess,
                AttributeError,
                NotImplementedError
            ):
                disk_read_bytes = None
                disk_write_bytes = None

            return {
                "pid": info["pid"],
                "name": info["name"],
                "executable_path": info["exe"],
                "parent_pid": info["ppid"],
                "process_create_time": info["create_time"],
                "cpu_percent": info["cpu_percent"],
                "memory_percent": info["memory_percent"],
                "memory_rss": (
                    memory_info.rss
                    if memory_info is not None
                    else None
                ),
                "disk_read_bytes": disk_read_bytes,
                "disk_write_bytes": disk_write_bytes,
                "username": info["username"],
                "status": info["status"],
                "timestamp": datetime.now(timezone.utc)
            }

    except psutil.NoSuchProcess:
        _PROCESS_CACHE.pop(pid, None)

        system_logger.debug(
            f"Process {pid} no longer exists."
        )
        return None

    except psutil.AccessDenied:
        error_logger.warning(
            f"Access denied while inspecting process {pid}."
        )
        return None

    except psutil.ZombieProcess:
        _PROCESS_CACHE.pop(pid, None)

        system_logger.debug(
            f"Process {pid} is a zombie process."
        )
        return None

    except psutil.Error as exc:
        error_logger.exception(
            f"Unable to inspect process {pid}: {exc}"
        )
        return None


def collect_running_processes() -> list[dict[str, Any]]:
    """
    Collect metadata from all accessible running processes.

    Individual process failures are skipped without
    interrupting the overall collection.

    Returns:
        A list of dictionaries containing process metadata.
    """

    try:
        process_ids = psutil.pids()

    except psutil.Error as exc:
        error_logger.exception(
            f"Unable to enumerate running processes: {exc}"
        )
        return []

    collected_processes = []

    active_pids = set(process_ids)

    # Remove cached objects for processes that no longer exist.
    stale_pids = set(_PROCESS_CACHE) - active_pids

    for stale_pid in stale_pids:
        _PROCESS_CACHE.pop(stale_pid, None)

    for pid in process_ids:

        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            system_logger.debug(
                f"Skipping invalid process ID: {pid!r}"
            )
            continue

        process_info = inspect_process(pid)

        if process_info is not None:
            collected_processes.append(process_info)

    system_logger.info(
        f"Process scan completed. "
        f"Collected {len(collected_processes)} of "
        f"{len(process_ids)} processes."
    )

    return collected_processes
