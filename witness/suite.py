"""Load the rules and their evidence, and check every rule against its evidence.

Each rule `rules/**/<stem>.yml` has a folder `evidence/<stem>/` holding:

  benign.jsonl   look-alike normal activity. The rule must fire on none of it.
  attack.jsonl   every process the attack started in the lab, written by
                 scripts/capture.ps1 and tagged with the Atomic test number ("_test").
                 For each test, the rule must fire on at least one of its events.
                 The rest (wrapper shells, cleanup) are kept as context.
  capture.json   how attack.jsonl was recorded: technique, Atomic test numbers, host,
                 Sysmon version and time. Also written by scripts/capture.ps1.

One event per line, as a flat JSON object of field name to value. Keys starting with
"_" are notes for people (such as "_note") and are never matched against.

A rule with no attack.jsonl yet is "awaiting" evidence: it is not counted as proven,
but it does not fail the build either. Missing a recorded test or firing on a benign
event does fail it.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sigma.rule import SigmaRule

from .evaluate import Event, UnsupportedRule, matches

ROOT = Path(__file__).resolve().parent.parent
RULES_DIR = ROOT / "rules"
EVIDENCE_DIR = ROOT / "evidence"

PROVEN = "proven"
AWAITING = "awaiting"
FAILING = "failing"


@dataclass
class Sample:
    event: Event
    note: str
    line: int
    test: int | None = None
    fired: bool = False


@dataclass
class RuleResult:
    path: Path
    rule: SigmaRule
    attack: list[Sample] = field(default_factory=list)
    benign: list[Sample] = field(default_factory=list)
    capture: dict[str, Any] | None = None
    errors: list[str] = field(default_factory=list)

    @property
    def stem(self) -> str:
        return self.path.stem

    @property
    def tests_run(self) -> list[int]:
        return sorted({s.test for s in self.attack if s.test is not None})

    @property
    def tests_detected(self) -> list[int]:
        return sorted({s.test for s in self.attack if s.test is not None and s.fired})

    @property
    def tests_missed(self) -> list[int]:
        return [t for t in self.tests_run if t not in self.tests_detected]

    @property
    def noisy(self) -> int:
        return sum(s.fired for s in self.benign)

    @property
    def status(self) -> str:
        if self.errors or self.noisy or self.tests_missed:
            return FAILING
        return PROVEN if self.attack else AWAITING

    @property
    def techniques(self) -> list[str]:
        return [t.name.upper() for t in self.rule.tags if t.namespace == "attack" and t.name[:1] == "t"]

    @property
    def tactics(self) -> list[str]:
        return [t.name for t in self.rule.tags if t.namespace == "attack" and t.name[:1] != "t"]


def rule_paths() -> list[Path]:
    return sorted(RULES_DIR.rglob("*.yml"))


def load_rule(path: Path) -> SigmaRule:
    return SigmaRule.from_yaml(path.read_text(encoding="utf-8"))


def load_samples(path: Path) -> list[Sample]:
    samples = []
    for number, line in enumerate(path.read_text(encoding="utf-8-sig").splitlines(), start=1):
        if not line.strip():
            continue
        raw = json.loads(line)
        event = {k: v for k, v in raw.items() if not k.startswith("_")}
        samples.append(Sample(event=event, note=raw.get("_note", ""), line=number, test=raw.get("_test")))
    return samples


def check_rule(path: Path) -> RuleResult:
    result = RuleResult(path=path, rule=load_rule(path))
    folder = EVIDENCE_DIR / path.stem

    benign_path = folder / "benign.jsonl"
    if benign_path.exists():
        result.benign = load_samples(benign_path)
        if not result.benign:
            result.errors.append(f"{benign_path.relative_to(ROOT).as_posix()} has no events")
    else:
        result.errors.append(f"missing {benign_path.relative_to(ROOT).as_posix()}")

    attack_path = folder / "attack.jsonl"
    if attack_path.exists():
        result.attack = load_samples(attack_path)
        capture_path = folder / "capture.json"
        if capture_path.exists():
            result.capture = json.loads(capture_path.read_text(encoding="utf-8-sig"))
        else:
            result.errors.append(f"{attack_path.name} has no capture.json saying how it was recorded")
        if not result.tests_run:
            result.errors.append(f"{attack_path.name} has no events tagged with an Atomic test number")

    try:
        for sample in result.attack + result.benign:
            sample.fired = matches(result.rule, sample.event)
    except UnsupportedRule as exc:
        result.errors.append(f"cannot evaluate rule: {exc}")

    return result


def check_all() -> list[RuleResult]:
    return [check_rule(path) for path in rule_paths()]
