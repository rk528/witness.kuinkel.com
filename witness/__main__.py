"""Command line: `python -m witness test` and `python -m witness build [--check]`."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import convert, site
from .suite import FAILING, ROOT, check_all, rule_paths


def cmd_test(_: argparse.Namespace) -> int:
    results = check_all()
    for r in results:
        attack = f"{len(r.tests_detected)}/{len(r.tests_run)} tests detected" if r.attack else "no capture yet"
        print(f"{r.status:9} {r.stem}  attack {attack}, benign {r.noisy}/{len(r.benign)} fired")
        for error in r.errors:
            print(f"          error: {error}")
        for test in r.tests_missed:
            print(f"          missed Atomic test {test}: no event from it matched")
        for s in r.benign:
            if s.fired:
                print(f"          fired on benign.jsonl line {s.line}: {s.note}")
    failing = [r for r in results if r.status == FAILING]
    print(f"\n{len(results)} rules, {len(failing)} failing")
    return 1 if failing else 0


def cmd_build(args: argparse.Namespace) -> int:
    outputs = convert.render_all(rule_paths())
    # The page embeds the queries, so write them before rendering it.
    if not args.check:
        _write(outputs)
    outputs.update(site.render_all(check_all()))

    if args.check:
        stale = [p for p, text in outputs.items() if not p.exists() or p.read_text(encoding="utf-8") != text]
        stale += _orphans(set(outputs))
        for path in stale:
            print(f"out of date: {path.relative_to(ROOT).as_posix()}")
        if stale:
            print("\nRun `python -m witness build` and commit the result.")
            return 1
        print("queries/ and site/ are up to date")
        return 0

    _write(outputs)
    for path in _orphans(set(outputs)):
        path.unlink()
    print(f"wrote {len(outputs)} files")
    return 0


def _write(outputs: dict[Path, str]) -> None:
    for path, text in outputs.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")


def _orphans(expected: set[Path]) -> list[Path]:
    """Generated query files whose rule no longer exists."""
    return [p for p in convert.QUERIES_DIR.rglob("*.*") if p not in expected]


def main() -> int:
    parser = argparse.ArgumentParser(prog="witness")
    sub = parser.add_subparsers(required=True)
    sub.add_parser("test", help="check every rule against its evidence").set_defaults(func=cmd_test)
    build = sub.add_parser("build", help="regenerate queries/ and site/")
    build.add_argument("--check", action="store_true", help="fail if the committed output is stale")
    build.set_defaults(func=cmd_build)
    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
