"""
Server-side terminal recording for SSH sessions (asciinema v2 / asciicast).

Captures what the target sends to the operator's terminal (output and
resizes), with timestamps, so a session can be replayed exactly. Keystrokes
are NOT captured: passwords typed at prompts are not echoed by the target
and therefore never reach the artifact. Commands appear because the shell
echoes them.

Artifacts live under RECORDING_STORAGE_PATH, which is not served by any
static route; the recordings API is the only way to read them. Each file is
created exclusively (O_EXCL) with mode 0600, and its SHA-256, size and
duration are computed when it is closed so playback can verify integrity.
"""

import hashlib
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from app.core.config import settings


class RecordingError(Exception):
    """The recording could not be started or completed."""


@dataclass(frozen=True)
class RecordingResult:
    file_size: int
    file_hash: str
    duration_seconds: int
    event_count: int


def storage_root() -> Path:
    return Path(settings.RECORDING_STORAGE_PATH).resolve()


def storage_writable() -> bool:
    """True when recordings can be created right now (directory exists or can be made, and is writable)."""
    root = storage_root()
    try:
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError:
        return False
    return os.access(root, os.W_OK | os.X_OK)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


class TerminalRecorder:
    def __init__(self, file_path: str) -> None:
        self._path = Path(file_path).resolve()
        self._handle = None
        self._started: Optional[float] = None
        self._events = 0

    @property
    def path(self) -> Path:
        return self._path

    def start(self, *, width: int, height: int, title: str) -> None:
        root = storage_root()
        if not self._path.is_relative_to(root):
            raise RecordingError("Recording path is outside the recording storage root")
        if not storage_writable():
            raise RecordingError("Recording storage is not writable")
        try:
            fd = os.open(self._path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except OSError as exc:
            raise RecordingError(f"Could not create recording file: {exc.strerror}") from exc
        self._handle = os.fdopen(fd, "w", encoding="utf-8")
        self._started = time.monotonic()
        header = {"version": 2, "width": width, "height": height,
                  "timestamp": int(time.time()), "title": title}
        self._write_line(header)

    def _write_line(self, value) -> None:
        if self._handle is None:
            raise RecordingError("Recording is not running")
        try:
            self._handle.write(json.dumps(value, ensure_ascii=False) + "\n")
            self._handle.flush()
        except (OSError, ValueError) as exc:
            raise RecordingError(f"Could not write recording: {exc}") from exc

    def _elapsed(self) -> float:
        return round(time.monotonic() - (self._started or time.monotonic()), 6)

    def output(self, data: str) -> None:
        if data:
            self._write_line([self._elapsed(), "o", data])
            self._events += 1

    def resize(self, cols: int, rows: int) -> None:
        self._write_line([self._elapsed(), "r", f"{cols}x{rows}"])
        self._events += 1

    @property
    def running(self) -> bool:
        return self._handle is not None

    def close(self) -> RecordingResult:
        """Flush, fsync and close; return integrity metadata. Raises RecordingError."""
        if self._handle is None:
            raise RecordingError("Recording was never started")
        duration = max(0, int(round(self._elapsed())))
        try:
            self._handle.flush()
            os.fsync(self._handle.fileno())
            self._handle.close()
        except OSError as exc:
            raise RecordingError(f"Could not finalize recording: {exc}") from exc
        finally:
            self._handle = None
        try:
            return RecordingResult(
                file_size=self._path.stat().st_size,
                file_hash=sha256_file(self._path),
                duration_seconds=duration,
                event_count=self._events,
            )
        except OSError as exc:
            raise RecordingError(f"Could not hash recording: {exc}") from exc
