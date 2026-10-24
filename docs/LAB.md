# Recording attack evidence in the lab

Attack evidence is recorded, not written by hand. A capture script runs Atomic Red Team
tests and keeps the Sysmon process events they produce:

- Linux rules: `scripts/capture.sh` in an Ubuntu VM
- Windows rules: `scripts/capture.ps1` in a Windows VM

**Only ever do this in an isolated VM you own, from a clean snapshot.** Atomic tests do
real things to the machine they run on.

## Linux (Ubuntu VM)

Tested target: Ubuntu 26.04 LTS in VMware Workstation, NAT network, 2 vCPUs, 4 GB RAM.
Take a snapshot called `clean` first.

### 1. Base tools

```sh
sudo apt update
sudo apt install -y git python3-venv curl
sudo snap install powershell --classic
```

### 2. Sysmon for Linux

Sysmon for Linux comes from Microsoft's package repository. Try your release first; if
Microsoft has not published 26.04 yet, the 24.04 package works on newer releases:

```sh
REL=$(lsb_release -rs)
curl -fsSLo /tmp/ms.deb "https://packages.microsoft.com/config/ubuntu/$REL/packages-microsoft-prod.deb" \
  || curl -fsSLo /tmp/ms.deb "https://packages.microsoft.com/config/ubuntu/24.04/packages-microsoft-prod.deb"
sudo dpkg -i /tmp/ms.deb
sudo apt update
sudo apt install -y sysmonforlinux
```

### 3. This repository

```sh
git clone https://github.com/rk528/witness.kuinkel.com.git ~/witness
cd ~/witness
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt
.venv/bin/python -m pytest -q          # should pass before you record anything
sudo sysmon -accepteula -i lab/sysmon-linux.xml
sudo journalctl -t sysmon -n 3 -o cat  # you should see <Event> lines
```

### 4. Atomic Red Team (installed for root, since captures run with sudo)

```sh
sudo pwsh -NoProfile -Command "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics -Force"
```

This puts everything in `/root/AtomicRedTeam`. Take a snapshot called `ready`.

### 5. Record a rule

Pick the tests that fit the rule. List them, and read the details of any test before
running it:

```sh
sudo pwsh -NoProfile -Command "Import-Module /root/AtomicRedTeam/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1; Invoke-AtomicTest T1548.001 -ShowDetailsBrief -PathToAtomicsFolder /root/AtomicRedTeam/atomics"
```

Then capture, using the numbers you picked:

```sh
sudo ./scripts/capture.sh proc_creation_lnx_chmod_setuid T1548.001 <n>
.venv/bin/python -m witness test
```

| Rule | Technique |
| --- | --- |
| proc_creation_lnx_chmod_setuid | T1548.001 |
| proc_creation_lnx_clear_shell_history | T1070.003 |
| proc_creation_lnx_crontab_from_temp | T1053.003 |
| proc_creation_lnx_reverse_shell_dev_tcp | T1059.004 |
| proc_creation_lnx_ssh_authorized_keys_write | T1098.004 |

Commit and push the new `evidence/<rule>/` folder, then revert the VM to `ready`.

## Windows (Windows VM)

Use the free Windows 11 Enterprise Evaluation ISO from Microsoft's Evaluation Center
(90 days, no licence key). VMware: 2 vCPUs, 6 GB RAM, 60 GB disk, NAT. Snapshot `clean`.

1. Turn off Tamper Protection, then real-time protection, inside the VM only
   (`Set-MpPreference -DisableRealtimeMonitoring $true`). Defender blocks many tests.
2. Install Sysmon with a config that logs process creation (Event ID 1), for example
   [sysmon-modular](https://github.com/olafhartong/sysmon-modular):
   `Sysmon64.exe -accepteula -i sysmonconfig.xml`
3. Install Invoke-AtomicRedTeam and the atomics:
   https://github.com/redcanaryco/invoke-atomicredteam/wiki/Installing-Invoke-AtomicRedTeam
4. `winget install Python.Python.3.12 Git.Git`, clone this repo, `py -m pip install -r requirements.txt`.
   Snapshot `ready`.
5. From an elevated PowerShell in the repo:

```powershell
Import-Module invoke-atomicredteam
Invoke-AtomicTest T1105 -ShowDetailsBrief
.\scripts\capture.ps1 -Rule proc_creation_win_certutil_download -Technique T1105 -TestNumbers <n>
py -m witness test
```

## What the capture writes

`evidence/<rule>/attack.jsonl` holds every process the tests started (found by following
parent PIDs down from the test runner), tagged with `_test`. `capture.json` records the
technique, tests, host, OS, Sysmon version and time. For each recorded test the rule
must fire on at least one of its events; the rest (wrapper shells, cleanup) is context.

If a rule misses a test, that is a finding: either the rule needs to cover that variant,
or the test is out of scope and should not be recorded for this rule.
