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


def test_follows_parents_that_were_never_logged():
    # The process tree recorded in the Ubuntu 26.04 lab: pwsh (22698) starts the test's
    # shell from worker thread 22727, and sudo (22771) runs chmod from a forked helper
    # (22773). Neither 22727 nor 22773 has a creation event of its own.
    journal = [
        _event(22698, 22697, "/snap/powershell/425/opt/powershell/pwsh", "pwsh -NoLogo"),
        _event(1300, 1, "/usr/sbin/cron", "cron -f"),
        _event(22761, 22727, "/usr/bin/dash", "sh -c sudo chmod u+xs /tmp/file"),
        _event(22771, 22761, "/usr/lib/cargo/bin/sudo", "sudo chmod u+xs /tmp/file"),
        _event(22774, 22773, "/usr/lib/cargo/bin/coreutils/chmod", "chmod u+xs /tmp/file"),
    ]
    kept = list(descendants(events_from_journal(journal), root_pid=22697))
    assert [e["ProcessId"] for e in kept] == [22698, 22761, 22771, 22774]


def test_skips_lines_that_are_not_xml_events():
    assert list(events_from_journal(["sysmon started", "<Event><broken"])) == []
