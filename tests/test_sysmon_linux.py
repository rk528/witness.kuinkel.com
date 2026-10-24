from witness.sysmon_linux import descendants, events_from_journal


def _event(pid: int, ppid: int, image: str, cmd: str, event_id: int = 1) -> str:
    return (
        "<Event><System><Provider Name=\"Linux-Sysmon\" Guid=\"{ff032593-a8d3-4f13-b0d6-01fc615a0f97}\"/>"
        f"<EventID>{event_id}</EventID><Computer>ubuntu-lab</Computer></System><EventData>"
        f"<Data Name=\"ProcessId\">{pid}</Data><Data Name=\"Image\">{image}</Data>"
        f"<Data Name=\"CommandLine\">{cmd}</Data><Data Name=\"ParentProcessId\">{ppid}</Data>"
        "</EventData></Event>"
    )


JOURNAL = [
    "-- Journal begins --",
    _event(100, 50, "/usr/bin/sh", "sh -c ls"),            # child of the runner
    _event(101, 100, "/usr/bin/ls", "ls -la"),             # grandchild
    _event(200, 1, "/usr/sbin/cron", "cron -f"),           # unrelated process
    _event(102, 100, "/usr/bin/ls", "ls", event_id=5),     # process exit, not creation
]


def test_parses_fields_and_types():
    first = next(events_from_journal(JOURNAL))
    assert first == {
        "EventID": 1,
        "Computer": "ubuntu-lab",
        "ProcessId": 100,
        "Image": "/usr/bin/sh",
        "CommandLine": "sh -c ls",
        "ParentProcessId": 50,
    }


def test_keeps_only_process_creations_below_the_runner():
    kept = list(descendants(events_from_journal(JOURNAL), root_pid=50))
    assert [e["ProcessId"] for e in kept] == [100, 101]


def test_skips_lines_that_are_not_xml_events():
    assert list(events_from_journal(["sysmon started", "<Event><broken"])) == []
