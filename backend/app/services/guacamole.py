"""
Guacamole protocol client for talking to guacd (the Apache Guacamole proxy daemon).

This is not an RDP implementation: guacd speaks RDP to the target. SecurePAM
only does what Guacamole's own web application does for a browser session:
select the protocol, answer guacd's `args` with the connection parameters
(including the credential, which therefore never leaves the backend), then
relay the instruction stream between guacd and the operator's browser.

Wire format: `LEN.value,LEN.value;` — each element is prefixed with its length
in Unicode characters. See the Guacamole protocol reference.
"""

import asyncio
import codecs
import re
from typing import Dict, List, Optional, Tuple

HANDSHAKE_TIMEOUT = 15.0
MAX_INSTRUCTION_CHARS = 8 * 1024 * 1024


class GuacamoleError(Exception):
    """guacd refused or failed the handshake. `code` is a stable, non-secret reason."""

    def __init__(self, code: str, message: str = "") -> None:
        super().__init__(message or code)
        self.code = code


def encode(*elements: str) -> str:
    return ",".join(f"{len(e)}.{e}" for e in elements) + ";"


class InstructionParser:
    """Incremental parser: feed text, get complete instructions as lists of strings."""

    def __init__(self) -> None:
        self._buf = ""

    def feed(self, text: str) -> List[List[str]]:
        self._buf += text
        if len(self._buf) > MAX_INSTRUCTION_CHARS:
            raise GuacamoleError("PROTOCOL_ERROR", "instruction too large")
        out: List[List[str]] = []
        while True:
            instruction, consumed = self._parse_one()
            if instruction is None:
                break
            out.append(instruction)
            self._buf = self._buf[consumed:]
        return out

    def _parse_one(self) -> Tuple[Optional[List[str]], int]:
        elements: List[str] = []
        pos = 0
        buf = self._buf
        while True:
            dot = buf.find(".", pos)
            if dot == -1:
                return None, 0
            digits = buf[pos:dot]
            if not digits.isdigit():
                raise GuacamoleError("PROTOCOL_ERROR", "malformed element length")
            length = int(digits)
            end = dot + 1 + length
            if len(buf) < end + 1:
                return None, 0
            elements.append(buf[dot + 1:end])
            terminator = buf[end]
            pos = end + 1
            if terminator == ";":
                return elements, pos
            if terminator != ",":
                raise GuacamoleError("PROTOCOL_ERROR", "malformed element terminator")


class GuacdStream:
    """A UTF-8 text view over a guacd TCP connection."""

    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader, self.writer = reader, writer
        self._decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
        self.parser = InstructionParser()
        self._pending: List[List[str]] = []

    async def read_instructions(self, timeout: Optional[float] = None) -> List[List[str]]:
        """Next batch of complete instructions (never empty). Raises on EOF."""
        while not self._pending:
            data = await asyncio.wait_for(self.reader.read(65536), timeout)
            if not data:
                raise GuacamoleError("GUACD_CLOSED", "guacd closed the connection")
            self._pending = self.parser.feed(self._decoder.decode(data))
        batch, self._pending = self._pending, []
        return batch

    async def read_chunk(self, timeout: Optional[float] = None) -> Tuple[str, List[List[str]]]:
        """One read from guacd: (raw text to relay unchanged, the complete instructions it finished)."""
        data = await asyncio.wait_for(self.reader.read(65536), timeout)
        if not data:
            raise GuacamoleError("GUACD_CLOSED", "guacd closed the connection")
        text = self._decoder.decode(data)
        return text, self.parser.feed(text)

    def take_pending(self) -> List[List[str]]:
        """Instructions already parsed during the handshake but not yet consumed."""
        batch, self._pending = self._pending, []
        return batch

    async def read_until(self, opcode: str, timeout: float) -> List[str]:
        deadline = asyncio.get_event_loop().time() + timeout
        while True:
            remaining = deadline - asyncio.get_event_loop().time()
            if remaining <= 0:
                raise GuacamoleError("GUACD_TIMEOUT", f"timed out waiting for {opcode}")
            batch = await self.read_instructions(remaining)
            for index, instruction in enumerate(batch):
                if instruction and instruction[0] == opcode:
                    self._pending = batch[index + 1:] + self._pending
                    return instruction
                if instruction and instruction[0] == "error":
                    raise GuacamoleError("GUACD_ERROR", instruction[1] if len(instruction) > 1 else "")

    def send(self, *elements: str) -> None:
        self.writer.write(encode(*elements).encode("utf-8"))

    def send_raw(self, text: str) -> None:
        self.writer.write(text.encode("utf-8"))

    async def close(self) -> None:
        try:
            self.writer.close()
            await asyncio.wait_for(self.writer.wait_closed(), 2)
        except Exception:
            pass


async def connect_guacd(host: str, port: int, timeout: float = 5.0) -> GuacdStream:
    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout)
    except (OSError, asyncio.TimeoutError) as exc:
        raise GuacamoleError("GUACD_UNREACHABLE", "guacd is not reachable") from exc
    return GuacdStream(reader, writer)


async def handshake(
    stream: GuacdStream, *, protocol: str, params: Dict[str, str], width: int, height: int, dpi: int,
) -> str:
    """Select the protocol and connect. Returns the guacd connection id from `ready`.

    guacd announces which parameters it accepts (`args`); we answer positionally. Parameters we do
    not set are sent empty so guacd applies its defaults; the leading VERSION_* element is echoed.
    """
    stream.send("select", protocol)
    args = await stream.read_until("args", HANDSHAKE_TIMEOUT)
    names = args[1:]
    stream.send("size", str(width), str(height), str(dpi))
    stream.send("audio")
    stream.send("video")
    stream.send("image", "image/png", "image/jpeg", "image/webp")
    stream.send("timezone", params.get("timezone", "UTC"))
    values = [name if name.startswith("VERSION_") else params.get(name, "") for name in names]
    stream.send("connect", *values)
    await stream.writer.drain()
    ready = await stream.read_until("ready", HANDSHAKE_TIMEOUT)
    return ready[1] if len(ready) > 1 else ""


# --- recordings ----------------------------------------------------------------------

_SYNC = re.compile(r"4\.sync,(\d+)\.(\d+)[,;]")


def looks_like_recording(head: bytes) -> bool:
    """A Guacamole recording is the raw instruction stream: it starts with `<len>.<opcode>,`."""
    return bool(re.match(rb"\d+\.[a-z]+[,;]", head[:64]))


def recording_duration_seconds(head: bytes, tail: bytes) -> Optional[int]:
    first = _SYNC.search(head.decode("utf-8", "replace"))
    last = None
    for last in _SYNC.finditer(tail.decode("utf-8", "replace")):
        pass
    if not first or last is None:
        return None
    return max(0, round((int(last.group(2)) - int(first.group(2))) / 1000))
