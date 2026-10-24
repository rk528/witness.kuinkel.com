<#
.SYNOPSIS
  Record the evidence for one Witness rule by running Atomic Red Team tests in a lab VM.

.DESCRIPTION
  Run this ONLY inside an isolated, snapshotted lab VM that you own. It:
    1. checks it is elevated and that Sysmon and Invoke-AtomicRedTeam are installed,
    2. runs each Atomic test you name (after fetching its prerequisites),
    3. keeps the Sysmon process-creation events (Event ID 1) for every process the test
       started, found by following parent process IDs down from this PowerShell session,
    4. runs each test's cleanup,
    5. writes evidence/<Rule>/attack.jsonl and evidence/<Rule>/capture.json.

  The script contains no attack commands of its own; everything it runs comes from the
  Atomic Red Team test definitions installed on the VM. Review those tests before you run
  them, and revert the VM to its snapshot afterwards.

.EXAMPLE
  .\scripts\capture.ps1 -Rule proc_creation_win_certutil_download -Technique T1105 -TestNumbers <n>
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)] [string] $Rule,
    [Parameter(Mandatory)] [ValidatePattern('^T\d{4}(\.\d{3})?$')] [string] $Technique,
    [Parameter(Mandatory)] [int[]] $TestNumbers,
    [int] $SettleSeconds = 5,
    [string] $RepoRoot = (Split-Path -Parent $PSScriptRoot)
)

$ErrorActionPreference = 'Stop'
$SysmonLog = 'Microsoft-Windows-Sysmon/Operational'

function Assert-Lab {
    $identity = [Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()
    if (-not $identity.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Run this from an elevated PowerShell session inside the lab VM.'
    }
    if (-not (Get-Service -Name 'Sysmon*' -ErrorAction SilentlyContinue | Where-Object Status -eq 'Running')) {
        throw 'Sysmon is not running. Install it with a config that logs Event ID 1.'
    }
    if (-not (Get-Command Invoke-AtomicTest -ErrorAction SilentlyContinue)) {
        throw 'Invoke-AtomicRedTeam is not loaded. Import-Module invoke-atomicredteam first.'
    }
    $ruleFile = Get-ChildItem -Path (Join-Path $RepoRoot 'rules') -Recurse -Filter "$Rule.yml"
    if (-not $ruleFile) { throw "No rule named $Rule under rules/." }
}

function ConvertTo-FlatEvent($record) {
    $xml = [xml]$record.ToXml()
    $flat = [ordered]@{
        EventID  = $record.Id
        Computer = $record.MachineName
    }
    foreach ($data in $xml.Event.EventData.Data) {
        $value = $data.'#text'
        if ($data.Name -in 'ProcessId', 'ParentProcessId', 'TerminalSessionId') { $value = [int64]$value }
        $flat[$data.Name] = $value
    }
    $flat
}

function Get-Descendants([object[]] $events, [int64] $rootPid) {
    # Events arrive oldest first, so a child is always seen after its parent.
    $pids = [System.Collections.Generic.HashSet[int64]]::new()
    [void]$pids.Add($rootPid)
    foreach ($e in $events) {
        if ($pids.Contains($e.ParentProcessId)) {
            [void]$pids.Add($e.ProcessId)
            $e
        }
    }
}

Assert-Lab

$outDir = Join-Path $RepoRoot "evidence\$Rule"
New-Item -ItemType Directory -Force -Path $outDir | Out-Null

$captured = New-Object System.Collections.Generic.List[object]
foreach ($test in $TestNumbers) {
    Write-Host "== $Technique test ${test}: prerequisites"
    Invoke-AtomicTest $Technique -TestNumbers $test -GetPrereqs | Out-Null

    $start = Get-Date
    Write-Host "== $Technique test ${test}: running"
    Invoke-AtomicTest $Technique -TestNumbers $test
    Start-Sleep -Seconds $SettleSeconds
    $end = Get-Date

    $records = Get-WinEvent -FilterHashtable @{ LogName = $SysmonLog; Id = 1; StartTime = $start; EndTime = $end } -ErrorAction SilentlyContinue
    $events = @($records | Sort-Object TimeCreated | ForEach-Object { ConvertTo-FlatEvent $_ })
    $ours = @(Get-Descendants $events $PID)
    Write-Host "   kept $($ours.Count) of $($events.Count) process events (descendants of PID $PID)"
    foreach ($e in $ours) {
        $e['_test'] = $test
        $captured.Add($e)
    }

    Write-Host "== $Technique test ${test}: cleanup"
    Invoke-AtomicTest $Technique -TestNumbers $test -Cleanup | Out-Null
}

if ($captured.Count -eq 0) { throw 'No process events were captured; nothing written.' }

$utf8 = New-Object System.Text.UTF8Encoding($false)
$lines = $captured | ForEach-Object { $_ | ConvertTo-Json -Compress -Depth 3 }
[System.IO.File]::WriteAllText((Join-Path $outDir 'attack.jsonl'), (($lines -join "`n") + "`n"), $utf8)

$sysmon = Get-Service -Name 'Sysmon*' | Select-Object -First 1
$sysmonVersion = (Get-Item (Get-CimInstance Win32_Service -Filter "Name='$($sysmon.Name)'").PathName.Trim('"')).VersionInfo.FileVersion
$capture = [ordered]@{
    technique      = $Technique
    tests          = $TestNumbers
    host           = $env:COMPUTERNAME
    os             = (Get-CimInstance Win32_OperatingSystem).Caption
    sysmon_version = $sysmonVersion
    captured_utc   = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm')
    events         = $captured.Count
}
[System.IO.File]::WriteAllText((Join-Path $outDir 'capture.json'), (($capture | ConvertTo-Json) + "`n"), $utf8)

Write-Host "`nWrote $($captured.Count) events to evidence\$Rule\attack.jsonl"
Write-Host 'Next: review the file, then run  python -m witness test  and  python -m witness build'
