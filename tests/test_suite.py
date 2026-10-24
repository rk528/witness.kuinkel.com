"""Every rule in the repo must hold against its evidence."""

import pytest

from witness.suite import FAILING, check_rule, rule_paths


@pytest.mark.parametrize("path", rule_paths(), ids=lambda p: p.stem)
def test_rule_holds_against_its_evidence(path):
    result = check_rule(path)
    assert not result.errors, result.errors
    assert [s.note for s in result.benign if s.fired] == [], "rule fired on benign events"
    assert result.tests_missed == [], "rule missed recorded Atomic tests"
    assert result.status != FAILING


def _write_rule_with_evidence(tmp_path, monkeypatch, attack_lines):
    import json

    from witness import suite

    rules = tmp_path / "rules"
    rules.mkdir()
    (rules / "notepad_print.yml").write_text(
        "title: Notepad prints a file\n"
        "logsource:\n  product: windows\n  category: process_creation\n"
        "detection:\n  s:\n    Image|endswith: '\\notepad.exe'\n    CommandLine|contains: ' /p '\n"
        "  condition: s\n",
        encoding="utf-8",
    )
    evidence = tmp_path / "evidence" / "notepad_print"
    evidence.mkdir(parents=True)
    (evidence / "benign.jsonl").write_text(
        json.dumps({"_note": "open a file", "Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad.exe a.txt"}) + "\n",
        encoding="utf-8",
    )
    if attack_lines is not None:
        (evidence / "attack.jsonl").write_text("".join(json.dumps(e) + "\n" for e in attack_lines), encoding="utf-8")
        (evidence / "capture.json").write_text('{"technique": "T0000", "tests": [1, 2]}', encoding="utf-8")
    monkeypatch.setattr(suite, "ROOT", tmp_path)
    monkeypatch.setattr(suite, "EVIDENCE_DIR", tmp_path / "evidence")
    return suite.check_rule(rules / "notepad_print.yml")


WRAPPER = {"Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c notepad.exe /p a.txt"}
HIT = {"Image": "C:\\Windows\\notepad.exe", "CommandLine": "notepad.exe /p a.txt"}


def test_rule_without_capture_is_awaiting(tmp_path, monkeypatch):
    from witness.suite import AWAITING

    assert _write_rule_with_evidence(tmp_path, monkeypatch, None).status == AWAITING


def test_every_recorded_test_must_be_detected(tmp_path, monkeypatch):
    from witness.suite import PROVEN

    proven = _write_rule_with_evidence(
        tmp_path, monkeypatch,
        [{**WRAPPER, "_test": 1}, {**HIT, "_test": 1}, {**HIT, "_test": 2}],
    )
    assert proven.status == PROVEN
    assert proven.tests_detected == [1, 2]


def test_a_missed_test_fails(tmp_path, monkeypatch):
    from witness.suite import FAILING

    result = _write_rule_with_evidence(
        tmp_path, monkeypatch,
        [{**HIT, "_test": 1}, {**WRAPPER, "_test": 2}],
    )
    assert result.status == FAILING
    assert result.tests_missed == [2]
