#!/usr/bin/env bash
# Record the evidence for one Witness Linux rule by running Atomic Red Team tests.
#
# Run this ONLY inside an isolated, snapshotted lab VM that you own. It:
#   1. checks it runs as root and that Sysmon for Linux, pwsh and Invoke-AtomicRedTeam exist,
#   2. runs each Atomic test you name (after fetching its prerequisites),
#   3. keeps the Sysmon process-creation events for every process the test started,
#   4. runs each test's cleanup,
#   5. writes evidence/<rule>/attack.jsonl and evidence/<rule>/capture.json.
#
# The script contains no attack commands of its own; everything it runs comes from the
# Atomic Red Team test definitions installed on the VM. Review them before running, and
# revert the VM to its snapshot afterwards.
#
# Usage: sudo ./scripts/capture.sh <rule> <technique> <test number>...
#   e.g. sudo ./scripts/capture.sh proc_creation_lnx_chmod_setuid T1548.001 <n>
set -euo pipefail

if [ "$#" -lt 3 ]; then
  echo "usage: sudo $0 <rule> <technique> <test number>..." >&2
  exit 2
fi

RULE="$1"; TECHNIQUE="$2"; shift 2; TESTS=("$@")
REPO="$(cd "$(dirname "$0")/.." && pwd)"
ATOMIC_HOME="${ATOMIC_HOME:-/root/AtomicRedTeam}"
PYTHON="${PYTHON:-$REPO/.venv/bin/python}"
SETTLE="${SETTLE:-5}"

fail() { echo "error: $*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || fail "run with sudo inside the lab VM"
[[ "$TECHNIQUE" =~ ^T[0-9]{4}(\.[0-9]{3})?$ ]] || fail "technique must look like T1234 or T1234.001"
for t in "${TESTS[@]}"; do [[ "$t" =~ ^[0-9]+$ ]] || fail "test numbers must be integers, got '$t'"; done
find "$REPO/rules" -name "$RULE.yml" | grep -q . || fail "no rule named $RULE under rules/"
systemctl is-active --quiet sysmon || fail "Sysmon for Linux is not running (systemctl status sysmon)"
command -v pwsh >/dev/null || fail "PowerShell (pwsh) is not installed"
[ -f "$ATOMIC_HOME/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1" ] || fail "Invoke-AtomicRedTeam not found under $ATOMIC_HOME"
[ -x "$PYTHON" ] || fail "no Python venv at $PYTHON (see docs/LAB.md)"

atomic() {
  pwsh -NoLogo -NoProfile -Command "Import-Module '$ATOMIC_HOME/invoke-atomicredteam/Invoke-AtomicRedTeam.psd1' -Force; Invoke-AtomicTest $TECHNIQUE -TestNumbers $1 -PathToAtomicsFolder '$ATOMIC_HOME/atomics' $2"
}

OUT="$REPO/evidence/$RULE"
mkdir -p "$OUT"
TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

for test in "${TESTS[@]}"; do
  echo "== $TECHNIQUE test $test: prerequisites"
  atomic "$test" "-GetPrereqs" >/dev/null

  echo "== $TECHNIQUE test $test: running"
  since="$(date '+%Y-%m-%d %H:%M:%S')"
  atomic "$test" "" &
  runner=$!
  wait "$runner" || echo "   (the test exited non-zero; keeping whatever it logged)"
  sleep "$SETTLE"
  until="$(date '+%Y-%m-%d %H:%M:%S')"

  journalctl -t sysmon -o cat --since "$since" --until "$until" --no-pager \
    | (cd "$REPO" && "$PYTHON" -m witness.sysmon_linux --root-pid "$runner" --test "$test") >> "$TMP"

  echo "== $TECHNIQUE test $test: cleanup"
  atomic "$test" "-Cleanup" >/dev/null || true
done

events=$(wc -l < "$TMP")
[ "$events" -gt 0 ] || fail "no process events were captured; nothing written"
cp "$TMP" "$OUT/attack.jsonl"

SYSMON_VERSION="$(dpkg-query -W -f='${Version}' sysmonforlinux 2>/dev/null || echo unknown)"
OS_NAME="$(. /etc/os-release && echo "$PRETTY_NAME")"
"$PYTHON" - "$OUT/capture.json" "$TECHNIQUE" "$events" "$SYSMON_VERSION" "$OS_NAME" "${TESTS[@]}" <<'PY'
import json, socket, sys
from datetime import datetime, timezone
path, technique, events, sysmon, os_name, *tests = sys.argv[1:]
capture = {
    "technique": technique,
    "tests": [int(t) for t in tests],
    "host": socket.gethostname(),
    "os": os_name,
    "sysmon_version": sysmon,
    "captured_utc": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M"),
    "events": int(events),
}
with open(path, "w", encoding="utf-8") as f:
    f.write(json.dumps(capture, indent=2) + "\n")
PY

# Hand the files back to the user who ran sudo, so git works without root.
if [ -n "${SUDO_USER:-}" ]; then chown -R "$SUDO_USER:" "$OUT"; fi

echo
echo "Wrote $events events to evidence/$RULE/attack.jsonl"
echo "Next: review the file, then run  .venv/bin/python -m witness test"
