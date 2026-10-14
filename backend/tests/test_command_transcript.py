"""Activity transcript tracker: observed input, masking, redaction, honesty."""

import hashlib
import json
import os
import stat

import pytest

from app.services.command_transcript import TranscriptTracker, transcript_path, write_transcript


def _tracker():
    now = [0.0]

    def tick(dt=1.0):
        now[0] += dt
    return TranscriptTracker(lambda: now[0]), tick


def test_command_with_output_and_timing():
    t, tick = _tracker()
    t.output("kali@kali:~$ ")
    tick()
    t.input("who"); t.input("ami"); tick(0.5); t.input("\r")
    t.output("whoami\r\nkali\r\nkali@kali:~$ ")
    tick()
    t.input("pwd\r")
    t.output("pwd\r\n/home/kali\r\nkali@kali:~$ ")
    a, b = t.events()
    assert (a["input"], a["t"], a["confidence"], a["execution_verified"]) == ("whoami", 1.0, "high", False)
    assert a["output"].startswith("kali") and "whoami" not in a["output"].splitlines()[0]
    assert b["input"] == "pwd" and "/home/kali" in b["output"] and b["t"] == 2.5


def test_echo_split_around_enter_does_not_leak_into_either_entry():
    """Real terminals echo typed characters asynchronously: 'ho' lands before Enter, 'stname' after."""
    t, tick = _tracker()
    t.output("kali@kali:~$ ")
    t.input("whoami\r")
    t.output("whoami\r\nkali\r\nkali@kali:~$ ")
    t.input("hostname")
    t.output("ho")
    t.input("\r")
    t.output("stname\r\nkali\r\nkali@kali:~$ ")
    a, b = t.events()
    assert a["output"] == "kali" and b["output"] == "kali"


def test_two_line_prompt_is_not_part_of_the_output():
    t, _ = _tracker()
    t.input("whoami\r")
    t.output("whoami\r\npam_lab\r\n\r\n┌──(pam_lab㉿kali)-[~]\r\n└─$ ")
    (e,) = t.events()
    assert e["output"] == "pam_lab"


def test_bracketed_paste_markers_bound_the_output_exactly_despite_prompt_redraws():
    """Recorded from a real Kali zsh session: the prompt line is redrawn on each keystroke,
    so echo cannot be matched by content; the shell's own markers delimit the command."""
    t, _ = _tracker()
    prompt = "\x1b[?2004h\x1b]0;u@kali: ~\x07\x1b[;32m┌──(\x1b[1;34mu㉿kali\x1b[;32m)-[~]\r\r\n└─$\x1b[0m "
    t.output(prompt)
    t.input("hostname")
    t.output("ho\r\x1b[;32m└─\x1b[1;34m$\x1b[0m \x1b[C\x1b[Cstn")
    t.input("\r")
    t.output("ame\r\n\x1b[?2004l\r\x1b]3008;start=abc;user=u\x1b\\kali\r\n\r\n" + prompt)
    t.input("pwd\r")
    t.output("pwd\r\n\x1b[?2004l\r/home/u\r\n" + prompt)
    a, b = t.events()
    assert (a["output"], b["output"]) == ("kali", "/home/u")


def test_backspace_and_ctrl_u_edit_the_line_exactly():
    t, _ = _tracker()
    t.input("lss\x7f\r")
    t.input("junk\x15echo hi\r")
    assert [e["input"] for e in t.events()] == ["ls", "echo hi"]


def test_secret_prompt_input_is_masked_not_stored():
    t, _ = _tracker()
    t.output("[sudo] password for kali: ")
    t.input("hunter2-CANARY\r")
    (e,) = t.events()
    assert "CANARY" not in json.dumps(e) and e["masked"] and e["confidence"] == "low"


def test_credentials_in_commands_and_output_are_redacted():
    t, _ = _tracker()
    t.input("export API_TOKEN=abc123CANARY\r")
    t.output("export...\r\n")
    t.input("curl -H 'Authorization: Bearer xyzCANARY' https://x\r")
    t.output("-----BEGIN OPENSSH PRIVATE KEY-----\r\nAAAA\r\n-----END OPENSSH PRIVATE KEY-----\r\n")
    events = t.events()
    assert "CANARY" not in json.dumps(events) and all(e["redacted"] for e in events)


def test_tab_and_history_lower_confidence():
    t, _ = _tracker()
    t.input("cat /et\t\r")
    t.input("\x1b[A\r")  # up-arrow recall: typed text is empty, so no entry is invented
    (e,) = t.events()
    assert e["edited"] and e["confidence"] == "low"


def test_fullscreen_programs_produce_no_entries():
    t, _ = _tracker()
    t.input("vim x\r")
    t.output("\x1b[?1049h")
    t.input("ihello\x1b:wq\r")
    t.output("\x1b[?1049l")
    assert [e["input"] for e in t.events()] == ["vim x"]


def test_bare_enter_and_empty_session_invent_nothing():
    t, _ = _tracker()
    t.input("\r\r")
    assert t.events() == []


def test_output_is_ansi_stripped_and_capped():
    t, _ = _tracker()
    t.input("cat big\r")
    t.output("\x1b[31m" + "x" * 9000 + "\x1b[0m")
    (e,) = t.events()
    assert "\x1b" not in e["output"] and len(e["output"]) == 4000 and e["output_truncated"]


def test_write_transcript_is_private_exclusive_and_hashed(tmp_path):
    rec = str(tmp_path / "session_x")
    t, _ = _tracker()
    t.input("id\r")
    meta = write_transcript(rec, session_number="SES-1", events=t.events())
    path = transcript_path(rec)
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert hashlib.sha256(path.read_bytes()).hexdigest() == meta["sha256"] and meta["events"] == 1
    doc = json.loads(path.read_text())
    assert doc["execution_verified"] is False and "not proof" in doc["limitations"]
    with pytest.raises(FileExistsError):
        write_transcript(rec, session_number="SES-1", events=[])
