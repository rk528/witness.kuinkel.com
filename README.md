# Witness

**Detections that have to prove themselves.** Live coverage: https://witness.kuinkel.com

Witness is a detection-as-code repository of [Sigma](https://sigmahq.io) rules for Windows.
A rule is not trusted because it looks right. It is trusted because CI shows, on every
commit, that it:

1. **catches the attack.** The technique is run with [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team)
   in an isolated lab VM, and the Sysmon events it leaves are saved next to the rule.
   The rule must fire on every recorded test.
2. **leaves normal work alone.** Each rule ships with look-alike benign activity (the
   admin commands that share its binaries and flags) and must fire on none of it.
3. **runs where analysts work.** Each rule is translated for Microsoft Sentinel (ASIM),
   Microsoft Defender XDR and Splunk, and the queries are committed under `queries/`.

The tests use their own small Sigma evaluator (`witness/evaluate.py`) that walks
pySigma's parsed condition tree against each event, so evidence is checked without
standing up a SIEM.

## Rules

| Rule | ATT&CK | Level |
| --- | --- | --- |
| LSASS memory dump via comsvcs.dll MiniDump | T1003.001 | high |
| PowerShell launched with an encoded command | T1059.001, T1027 | medium |
| File download with certutil | T1105 | high |
| Scheduled task created to run from a user-writable folder | T1053.005 | medium |
| Shadow copies or backup catalog deleted | T1490 | high |

The status of each rule (proven in the lab, or awaiting capture) is on the
[coverage page](https://witness.kuinkel.com).

## Layout

```
rules/       Sigma rules, one per file
evidence/    per rule: benign.jsonl, and once captured attack.jsonl + capture.json
queries/     generated Sentinel, Defender XDR and Splunk queries (committed)
site/        generated coverage page, deployed to witness.kuinkel.com
witness/     the evaluator, test suite, converters and page renderer
scripts/     capture.ps1, which records attack evidence in the lab
```

## Use it

```sh
python -m venv .venv && . .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -r requirements.txt
python -m pytest -q          # evaluator unit tests + every rule against its evidence
python -m witness test       # readable per-rule report
python -m witness build      # regenerate queries/ and site/
```

CI runs all three, and `python -m witness build --check` fails if the committed queries or
page no longer match the rules.

## Adding a rule

1. Write the rule in `rules/windows/<category>/`, tagged with its ATT&CK tactic and technique.
2. Add `evidence/<rule file name>/benign.jsonl`: the closest normal activity you can think
   of, one Sysmon-style JSON event per line with a `_note` saying what it is.
3. Record the attack in the lab (see [docs/LAB.md](docs/LAB.md)).
4. Run `python -m witness test`, then `python -m witness build`, and commit everything.

## Notes

- pySigma's ASIM pipeline maps `OriginalFileName` to a column that `imProcessCreate` does
  not have and then rejects its own output. `witness/convert.py` maps the field first.
- Evidence events use Sysmon field names, which match Sigma's `process_creation` taxonomy.

## License

MIT. Built by [Raghav Kuinkel](https://raghav.kuinkel.com).
