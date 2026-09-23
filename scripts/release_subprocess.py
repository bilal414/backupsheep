"""Bound release subprocesses and terminate their entire descendant process group."""

from __future__ import annotations

import os
import signal
import subprocess
import threading
from collections.abc import Mapping, Sequence


def _terminate_group(process: subprocess.Popen[str]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        return
    try:
        process.communicate(timeout=5)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.communicate(timeout=5)


def run_text(
    command: Sequence[str],
    *,
    environment: Mapping[str, str],
    timeout: int,
) -> subprocess.CompletedProcess[str]:
    """Run one command in a new session with timeout and signal-safe cleanup."""

    process = subprocess.Popen(
        list(command),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=dict(environment),
        start_new_session=True,
    )
    previous_handlers: dict[int, object] = {}

    def forward_signal(signum, _frame):  # noqa: ANN001
        _terminate_group(process)
        raise SystemExit(128 + signum)

    if threading.current_thread() is threading.main_thread():
        for signum in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM):
            previous_handlers[signum] = signal.getsignal(signum)
            signal.signal(signum, forward_signal)
    try:
        try:
            stdout, stderr = process.communicate(timeout=timeout)
        except subprocess.TimeoutExpired:
            _terminate_group(process)
            raise
    finally:
        for signum, handler in previous_handlers.items():
            signal.signal(signum, handler)
    return subprocess.CompletedProcess(
        args=list(command),
        returncode=process.returncode,
        stdout=stdout,
        stderr=stderr,
    )
