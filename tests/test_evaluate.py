import pytest
from sigma.rule import SigmaRule

from witness.evaluate import matches


def rule(detection: str) -> SigmaRule:
    return SigmaRule.from_yaml(
        "title: test\nlogsource:\n  product: windows\n  category: process_creation\n"
        "detection:\n" + detection
    )


NOTEPAD = {"Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe /p C:\\notes\\todo.txt"}


@pytest.mark.parametrize(
    ("detection", "expected"),
    [
        ("  s:\n    Image|endswith: '\\notepad.exe'\n  condition: s\n", True),
        ("  s:\n    Image|endswith: '\\NOTEPAD.EXE'\n  condition: s\n", True),
        ("  s:\n    Image|endswith: '\\calc.exe'\n  condition: s\n", False),
        ("  s:\n    Image|startswith: 'C:\\Windows\\'\n  condition: s\n", True),
        ("  s:\n    Image: 'C:\\Windows\\System32\\notepad.exe'\n  condition: s\n", True),
        ("  s:\n    Image: 'notepad.exe'\n  condition: s\n", False),
        ("  s:\n    Image: '*\\note?ad.exe'\n  condition: s\n", True),
    ],
)
def test_string_modifiers(detection, expected):
    assert matches(rule(detection), NOTEPAD) is expected


def test_contains_all_needs_every_value():
    both = "  s:\n    CommandLine|contains|all: ['/p', 'todo']\n  condition: s\n"
    one = "  s:\n    CommandLine|contains|all: ['/p', 'missing']\n  condition: s\n"
    assert matches(rule(both), NOTEPAD)
    assert not matches(rule(one), NOTEPAD)


def test_list_of_values_is_or():
    assert matches(rule("  s:\n    CommandLine|contains: ['nothing', 'todo']\n  condition: s\n"), NOTEPAD)


def test_windash_accepts_slash_and_dash():
    detection = "  s:\n    CommandLine|windash|contains: ' -p '\n  condition: s\n"
    assert matches(rule(detection), {"CommandLine": "notepad.exe /p a.txt"})
    assert matches(rule(detection), {"CommandLine": "notepad.exe -p a.txt"})
    assert not matches(rule(detection), {"CommandLine": "notepad.exe a.txt"})


def test_selector_and_not():
    detection = (
        "  sel_a:\n    Image|endswith: '\\notepad.exe'\n"
        "  sel_b:\n    CommandLine|contains: 'todo'\n"
        "  filter:\n    User: 'LAB\\admin'\n"
        "  condition: all of sel_* and not filter\n"
    )
    assert matches(rule(detection), NOTEPAD)
    assert not matches(rule(detection), {**NOTEPAD, "User": "LAB\\admin"})
    assert not matches(rule(detection), {**NOTEPAD, "CommandLine": "notepad.exe"})


def test_one_of():
    detection = "  sel_a:\n    Image|endswith: '\\calc.exe'\n  sel_b:\n    CommandLine|contains: 'todo'\n  condition: 1 of sel_*\n"
    assert matches(rule(detection), NOTEPAD)


def test_cased_modifier_is_case_sensitive():
    detection = "  s:\n    CommandLine|cased|contains: 'TODO'\n  condition: s\n"
    assert not matches(rule(detection), NOTEPAD)


def test_regex_is_unanchored_and_case_sensitive_by_default():
    assert matches(rule("  s:\n    CommandLine|re: 'notes\\\\[a-z]+\\.txt'\n  condition: s\n"), NOTEPAD)
    assert not matches(rule("  s:\n    CommandLine|re: 'NOTES'\n  condition: s\n"), NOTEPAD)
    assert matches(rule("  s:\n    CommandLine|re|i: 'NOTES'\n  condition: s\n"), NOTEPAD)


def test_missing_field_never_matches_a_value():
    assert not matches(rule("  s:\n    ParentImage|endswith: '.exe'\n  condition: s\n"), NOTEPAD)
    assert matches(rule("  s:\n    ParentImage: null\n  condition: s\n"), NOTEPAD)


def test_exists_modifier():
    assert matches(rule("  s:\n    Image|exists: true\n  condition: s\n"), NOTEPAD)
    assert matches(rule("  s:\n    ParentImage|exists: false\n  condition: s\n"), NOTEPAD)


def test_numbers_and_comparisons():
    event = {"EventID": 1, "ProcessId": "4242"}
    assert matches(rule("  s:\n    EventID: 1\n  condition: s\n"), event)
    assert matches(rule("  s:\n    ProcessId|gt: 4000\n  condition: s\n"), event)
    assert not matches(rule("  s:\n    ProcessId|lt: 4000\n  condition: s\n"), event)


def test_cidr():
    detection = "  s:\n    DestinationIp|cidr: '10.0.0.0/8'\n  condition: s\n"
    assert matches(rule(detection), {"DestinationIp": "10.1.2.3"})
    assert not matches(rule(detection), {"DestinationIp": "192.168.1.4"})


def test_field_names_fall_back_to_case_insensitive():
    assert matches(rule("  s:\n    image|endswith: '\\notepad.exe'\n  condition: s\n"), NOTEPAD)


def test_keywords_search_every_field():
    assert matches(rule("  keywords:\n    - 'todo.txt'\n  condition: keywords\n"), NOTEPAD)
    assert not matches(rule("  keywords:\n    - 'absent'\n  condition: keywords\n"), NOTEPAD)


@pytest.mark.parametrize(
    ("cmd", "expected"),
    [
        ("chmod 4755 /usr/local/bin/helper", True),
        ("/usr/bin/chmod -v 2775 /srv/shared ", True),
        ("chmod u+s /usr/local/bin/helper", True),
        ("chmod u+xs /usr/local/bin/helper", True),
        ("chmod u+x,g+s /srv/shared", True),
        ("chmod ug=rwxs /srv/shared", True),
        ("chmod 0755 /usr/local/bin/helper", False),
        ("chmod 644 notes.txt", False),
        ("chmod +x setup.sh", False),
        ("chmod g-s /srv/shared", False),
        ("chmod u=rwx,go=rx scripts", False),
    ],
)
def test_chmod_setuid_rule_modes(cmd, expected):
    from witness.suite import RULES_DIR

    chmod = SigmaRule.from_yaml(
        (RULES_DIR / "linux" / "process_creation" / "proc_creation_lnx_chmod_setuid.yml").read_text(encoding="utf-8")
    )
    assert matches(chmod, {"Image": "/usr/lib/cargo/bin/coreutils/chmod", "CommandLine": cmd}) is expected
