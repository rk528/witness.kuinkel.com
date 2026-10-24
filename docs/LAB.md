# Recording attack evidence in the lab

Attack evidence is recorded, not written by hand. `scripts/capture.ps1` runs Atomic Red
Team tests and keeps the Sysmon process events they produce.

**Only ever do this in an isolated VM you own, from a clean snapshot.** Atomic tests do
real things: they dump credentials, delete shadow copies and change persistence settings.

## One-time VM setup

1. A Windows 10/11 VM in VMware Workstation, on a host-only or NAT network. Take a snapshot
   called `clean` before installing anything else.
2. Turn off Microsoft Defender real-time protection in the VM (several tests are blocked by
   it, which is good for a real host but stops the capture).
3. Install Sysmon with a configuration that logs process creation (Event ID 1), for example
   the SwiftOnSecurity or Olaf Hartong configs:
   `sysmon64.exe -accepteula -i sysmonconfig.xml`
4. Install Invoke-AtomicRedTeam and the atomics folder, following
   https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam
5. Copy or clone this repository into the VM and take a second snapshot, `ready`.

## Recording one rule

From an elevated PowerShell in the repository folder:

```powershell
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1105 -ShowDetailsBrief        # pick the test numbers that fit the rule
.\scripts\capture.ps1 -Rule proc_creation_win_certutil_download -Technique T1105 -TestNumbers <n>
```

Read each test's details (`-ShowDetails`) before running it. The script writes
`evidence/<rule>/attack.jsonl` (every process the tests started, tagged with the test
number) and `capture.json` (technique, tests, host, OS, Sysmon version, time).

Then:

```powershell
python -m witness test     # the rule must detect every recorded test
python -m witness build
```

Copy the evidence folder out of the VM, commit it, and revert the VM to `ready`.

If a rule misses a test, that is a finding: either the rule needs to cover that variant,
or the test is out of scope and should not be recorded for this rule.
