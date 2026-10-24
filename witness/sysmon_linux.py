"""Turn Sysmon for Linux journal output into Witness evidence lines.

Sysmon for Linux logs each event to syslog as one XML <Event> document. capture.sh
pipes `journalctl -t sysmon -o cat` through this module, which keeps the process-creation
events (Event ID 1) for every process descended from the Atomic test runner and writes
them as JSON lines tagged with the test number.

    journalctl -t sysmon -o cat --since ... | python -m witness.sysmon_linux --root-pid 4242 --test 1
"""

from __future__ import annotations

import argparse
import json
import sys
import xml.etree.ElementTree as ET
from typing import Iterable, Iterator

INT_FIELDS = {"ProcessId", "ParentProcessId", "LogonId"}


def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def parse_event(xml_text: str) -> dict | None:
    """One flat dict from one <Event> document, or None if it is not an event."""
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return None
    if _local(root.tag) != "Event":
        return None
    event: dict = {}
    for child in root:
        if _local(child.tag) == "System":
            for item in child:
                name = _local(item.tag)
                if name == "EventID":
                    event["EventID"] = int((item.text or "0").strip())
                elif name == "Computer":
                    event["Computer"] = (item.text or "").strip()
        elif _local(child.tag) == "EventData":
            for data in child:
                name = data.get("Name")
                if not name:
                    continue
                value = data.text if data.text is not None else ""
                if name in INT_FIELDS and value.strip().lstrip("-").isdigit():
                    event[name] = int(value)
                else:
                    event[name] = value
    return event


def events_from_journal(lines: Iterable[str]) -> Iterator[dict]:
    for line in lines:
        start = line.find("<Event")
        if start == -1:
            continue
        event = parse_event(line[start:].strip())
        if event is not None:
            yield event


def descendants(events: Iterable[dict], root_pid: int) -> Iterator[dict]:
    """Process-creation events below root_pid. Events must be oldest first."""
    pids = {root_pid}
    for event in events:
        if event.get("EventID") != 1:
            continue
        if event.get("ParentProcessId") in pids:
            pids.add(event.get("ProcessId"))
            yield event


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m witness.sysmon_linux")
    parser.add_argument("--root-pid", type=int, required=True, help="PID of the process that ran the test")
    parser.add_argument("--test", type=int, required=True, help="Atomic test number to tag events with")
    args = parser.parse_args(argv)

    kept = 0
    for event in descendants(events_from_journal(sys.stdin), args.root_pid):
        event["_test"] = args.test
        sys.stdout.write(json.dumps(event) + "\n")
        kept += 1
    print(f"kept {kept} process events below PID {args.root_pid}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
