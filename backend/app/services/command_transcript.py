"""
Activity transcript for SSH sessions, derived while the session runs.

What it is: the lines an operator typed (observed terminal input) with the
terminal output that followed each one, timed on the same clock as the
asciicast recording so the UI can seek the replay to a command.

What it is NOT: proof of execution. The gateway sees keystrokes and output;
it does not see the target's shell. A typed line may be edited by tab
completion or history (flagged low confidence), typed into a program rather
than a shell, or fail. Nothing here is "verified command execution"; that
needs trusted shell auditing on the target (auditd, sudo I/O logging), which
this does not integrate. Command boundaries are only ever Enter keypresses.

Secrets: input typed at a password/passphrase/token prompt is never stored
(it is not echoed by the target either), full-screen programs (vim, less)
produce no entries, and obvious credential patterns in commands or output
are replaced with [REDACTED]. Redaction is best-effort pattern matching.

The transcript is a separate artifact from the recording (which stays the
original evidence); it is stored next to it with its own SHA-256.
"""

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Callable, List, Optional

TRANSCRIPT_SUFFIX = ".transcript.json"
MAX_OUTPUT_CHARS = 4000
MAX_COMMAND_CHARS = 2000
MAX_EVENTS = 5000
RAW_HEAD_LIMIT = 128 * 1024
RAW_TAIL_LIMIT = 32 * 1024
_PASTE_OFF = "\x1b[?2004l"
_PASTE_ON = "\x1b[?2004h"

SOURCE = "terminal_input_observed"
LIMITATIONS = (
    "Entries are lines typed by the operator, observed at the gateway, with the terminal output that followed. "
    "They are not proof the target executed them (typed text may be edited by completion or history, entered "
    "into a non-shell program, or have failed). Secrets typed at password prompts are never recorded."
)

_ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b[@-Z\\-_]|\x1b[()][A-Za-z0-9]")
_SECRET_PROMPT = re.compile(
    r"(pass(word|phrase|code)|\bpin\b|token|secret|otp|verification code|credential)[^\n]{0,60}[:?]\s*$", re.I)
_REDACT = [
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)(authorization[ \t]*:[ \t]*(?:bearer|basic|token)?[ \t]*)[^\s'\"]+"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(bearer[ \t]+)[A-Za-z0-9._~+/=-]{8,}"), r"\1[REDACTED]"),
    (re.compile(r"(?i)([A-Za-z0-9_.-]*(?:pass(?:word|wd)?|secret|token|api[_-]?key|access[_-]?key|credential)[A-Za-z0-9_.-]*"
                r"[ \t]*[=:][ \t]*)(\"[^\"]*\"|'[^']*'|[^\s'\"]+)"), r"\1[REDACTED]"),
    (re.compile(r"(?i)(--(?:pass(?:word)?|token|secret|api-key)[= ])(\S+)"), r"\1[REDACTED]"),
]
_PROMPT_TAIL = re.compile(r"[$#%>❯»] ?$")
# Two-line prompts (zsh/Kali style: "┌──(user㉿host)-[~]" then "└─$ ") trail the output of the command before them.
_PROMPT_BLOCK = re.compile(r"\n*(?:┌[^\n]*(?:\n+└[^\n]{0,12})?|└[^\n]{0,12})\s*$")
_ALT_ON = ("\x1b[?1049h", "\x1b[?47h", "\x1b[?1047h")
_ALT_OFF = ("\x1b[?1049l", "\x1b[?47l", "\x1b[?1047l")


def clean_text(text: str) -> str:
    text = _ANSI.sub("", text).replace("\r\n", "\n").replace("\r", "\n")
    return "".join(ch for ch in text if ch == "\n" or ch == "\t" or ord(ch) >= 32)


def redact(text: str) -> tuple[str, bool]:
    out = text
    for pattern, repl in _REDACT:
        out = pattern.sub(repl, out)
    return out, out != text


class TranscriptTracker:
    """Feed it the same input/output the recorder sees; call events() at the end."""

    def __init__(self, clock: Callable[[], float]) -> None:
        self._clock = clock
        self._events: List[dict] = []
        self._line: List[str] = []
        self._line_t: Optional[float] = None
        self._edited = False
        self._masked = False
        self._escape = ""
        self._alt_screen = False
        self._recent_output = ""
        self._pending_echo = ""  # typed characters the target has not echoed back yet
        self._current: Optional[dict] = None
        self._out_parts: List[str] = []  # echo-filtered text (fallback when the shell has no markers)
        self._raw_head: List[str] = []
        self._raw_head_size = 0
        self._raw_tail = ""
        self._truncated_events = False

    # --- output ---------------------------------------------------------
    def output(self, data: str) -> None:
        for marker in _ALT_ON:
            if marker in data:
                self._alt_screen = True
        for marker in _ALT_OFF:
            if marker in data:
                self._alt_screen = False
        self._recent_output = (self._recent_output + data)[-400:]
        if self._current is not None and not self._alt_screen:
            self._out_parts.append(self._without_echo(data))
            if sum(len(p) for p in self._out_parts) > MAX_OUTPUT_CHARS * 4:
                self._out_parts = self._out_parts[:1] + self._out_parts[-8:]
            if self._raw_head_size < RAW_HEAD_LIMIT:
                self._raw_head.append(data)
                self._raw_head_size += len(data)
            else:
                self._raw_tail = (self._raw_tail + data)[-RAW_TAIL_LIMIT:]

    def _without_echo(self, data: str) -> str:
        """Drop the shell's echo of what was just typed. Echo arrives asynchronously, so it can land
        before or after the Enter that ends the line; matching it by content keeps it out of every
        entry's output. Any other printable character means the echo has ended or diverged."""
        text = clean_text(data).replace("\b \b", "")
        kept = []
        for ch in text:
            if self._pending_echo and ch == self._pending_echo[0]:
                self._pending_echo = self._pending_echo[1:]
            else:
                if ch >= " " and ch != "\x7f":
                    self._pending_echo = ""
                kept.append(ch)
        return "".join(kept)

    # --- input ----------------------------------------------------------
    def input(self, data: str) -> None:
        for ch in data:
            if self._escape == "esc":
                # ESC [ starts a CSI sequence, ESC O a one-char SS3 sequence; anything else is Alt+key.
                self._escape = "csi" if ch == "[" else "ss3" if ch == "O" else ""
                continue
            if self._escape == "csi":
                if "@" <= ch <= "~":  # final byte
                    self._escape = ""
                continue
            if self._escape == "ss3":
                self._escape = ""
                continue
            if ch == "\x1b":
                self._escape = "esc"
                self._edited = True  # arrows / history / cursor movement make typed text unreliable
                continue
            if self._alt_screen:
                continue
            if ch in "\r\n":
                self._enter()
            elif ch in "\x7f\x08":
                if self._line:
                    self._line.pop()
            elif ch == "\x15" or ch == "\x03":  # Ctrl-U / Ctrl-C discard the line
                self._reset_line()
            elif ch == "\x17":  # Ctrl-W
                text = "".join(self._line).rstrip()
                self._line = list(text[: text.rfind(" ") + 1]) if " " in text else []
            elif ch == "\t":
                self._edited = True  # completion inserts text we cannot see from keystrokes
            elif ch >= " ":
                if not self._line and self._line_t is None:
                    self._line_t = self._clock()
                    self._masked = bool(_SECRET_PROMPT.search(clean_text(self._recent_output)))
                if not self._masked:
                    self._line.append(ch)
                    self._pending_echo = (self._pending_echo + ch)[-256:]
                if self._line_t is None:
                    self._line_t = self._clock()

    def _reset_line(self) -> None:
        self._line, self._line_t, self._edited, self._masked = [], None, False, False

    def _enter(self) -> None:
        text = "".join(self._line)
        masked = self._masked
        if not masked and not text.strip():
            self._reset_line()
            self._finish_current()  # a bare Enter: output so far belongs to the previous entry
            return
        self._finish_current()
        t = self._line_t if self._line_t is not None else self._clock()
        if len(self._events) >= MAX_EVENTS:
            self._truncated_events = True
            self._reset_line()
            return
        redacted = False
        if masked:
            shown = "[masked: input at a secret prompt]"
        else:
            shown, redacted = redact(text[:MAX_COMMAND_CHARS])
        self._current = {
            "seq": len(self._events) + 1,
            "t": round(t, 3),
            "t_enter": round(self._clock(), 3),
            "input": shown,
            "masked": masked,
            "redacted": redacted,
            "edited": self._edited,
            "confidence": "low" if (self._edited or masked) else "high",
            "source": SOURCE,
            "execution_verified": False,
            "output": "",
            "output_truncated": False,
        }
        self._events.append(self._current)
        self._reset_output()
        self._reset_line()

    def _finish_current(self) -> None:
        if self._current is None:
            return
        raw = self._command_output()
        # An unterminated last line that ends like a prompt is the next prompt, not output.
        raw = _PROMPT_BLOCK.sub("", raw)
        head, sep, last = raw.rpartition("\n")
        if last and _PROMPT_TAIL.search(last):
            raw = head
        raw, out_redacted = redact(raw)
        raw = raw.rstrip()
        if len(raw) > MAX_OUTPUT_CHARS:
            raw, self._current["output_truncated"] = raw[:MAX_OUTPUT_CHARS], True
        self._current["output"] = raw
        self._current["redacted"] = self._current["redacted"] or out_redacted
        self._current = None
        self._reset_output()

    def _reset_output(self) -> None:
        self._out_parts, self._raw_head, self._raw_head_size, self._raw_tail = [], [], 0, ""

    def _command_output(self) -> str:
        """Output of the current entry. Shells with bracketed paste (bash, zsh, fish) print ESC[?2004l when a
        line is accepted and ESC[?2004h when the next prompt starts, which bounds the command's output exactly,
        independent of how the prompt line is redrawn. Without those markers, fall back to echo filtering."""
        raw = "".join(self._raw_head) + self._raw_tail
        if _PASTE_OFF in raw:
            body = raw.split(_PASTE_OFF, 1)[1].split(_PASTE_ON, 1)[0]
            return clean_text(body).lstrip("\n")
        return "".join(self._out_parts).lstrip("\n")

    def events(self) -> List[dict]:
        """Finalize and return the entries. Call once, at session end."""
        self._finish_current()
        return list(self._events)

    @property
    def truncated(self) -> bool:
        return self._truncated_events


def transcript_path(recording_file_path: str) -> Path:
    return Path(f"{recording_file_path}{TRANSCRIPT_SUFFIX}")


def write_transcript(recording_file_path: str, *, session_number: str, events: List[dict],
                     truncated: bool = False) -> dict:
    """Write the transcript next to (not inside) the recording: exclusive create, mode 0600.
    Returns {"sha256", "events", "bytes"} for the recording's metadata."""
    document = {
        "version": 1, "session": session_number, "source": SOURCE, "limitations": LIMITATIONS,
        "execution_verified": False, "events_truncated": truncated, "events": events,
    }
    payload = json.dumps(document, ensure_ascii=False, indent=1).encode("utf-8")
    path = transcript_path(recording_file_path)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as handle:
        handle.write(payload)
        handle.flush()
        os.fsync(handle.fileno())
    return {"sha256": hashlib.sha256(payload).hexdigest(), "events": len(events), "bytes": len(payload)}
