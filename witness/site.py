"""Render the public coverage page from the suite results.

The page is plain static HTML with no scripts, written to `site/` and served as is.
It is built from the same results the tests use, so it cannot claim more than CI proves.
"""

from __future__ import annotations

import json
from html import escape

from .convert import TARGETS, query_path
from .suite import AWAITING, FAILING, PROVEN, ROOT, RuleResult

SITE_DIR = ROOT / "site"
REPO_URL = "https://github.com/rk528/witness.kuinkel.com"

TACTICS = [
    "reconnaissance", "resource-development", "initial-access", "execution", "persistence",
    "privilege-escalation", "defense-evasion", "credential-access", "discovery",
    "lateral-movement", "collection", "command-and-control", "exfiltration", "impact",
]

STATUS_LABEL = {
    PROVEN: "Proven in the lab",
    AWAITING: "Awaiting lab capture",
    FAILING: "Failing",
}


def _tactic_name(tactic: str) -> str:
    return tactic.replace("-", " ").title().replace("And", "and")


def _technique_url(technique: str) -> str:
    return "https://attack.mitre.org/techniques/" + technique.replace(".", "/") + "/"


def coverage(results: list[RuleResult]) -> dict:
    return {
        "rules": [
            {
                "id": str(r.rule.id),
                "title": r.rule.title,
                "file": r.path.relative_to(ROOT).as_posix(),
                "platform": _platform(r),
                "level": r.rule.level.name.lower() if r.rule.level else None,
                "tactics": r.tactics,
                "techniques": r.techniques,
                "status": r.status,
                "attack": {"events": len(r.attack), "tests_run": r.tests_run, "tests_detected": r.tests_detected},
                "benign": {"events": len(r.benign), "fired": r.noisy},
                "capture": r.capture,
            }
            for r in results
        ]
    }


def _platform(r: RuleResult) -> str:
    product = r.rule.logsource.product or "any"
    return {"windows": "Windows", "linux": "Linux"}.get(product, product)


def _badge(status: str) -> str:
    return f'<span class="badge {status}">{STATUS_LABEL[status]}</span>'


def _matrix(results: list[RuleResult]) -> str:
    columns = []
    for tactic in TACTICS:
        chips = []
        for r in results:
            if tactic in r.tactics:
                for t in r.techniques:
                    chips.append(
                        f'<a class="chip {r.status}" href="#{r.stem}" title="{escape(r.rule.title)}">{t}</a>'
                    )
        body = "".join(chips) or '<span class="empty">No rules yet</span>'
        columns.append(
            f'<div class="tactic{" none" if not chips else ""}"><h3>{_tactic_name(tactic)}</h3>{body}</div>'
        )
    return "".join(columns)


def _evidence(r: RuleResult) -> str:
    rows = []
    for s in r.benign:
        ok = not s.fired
        rows.append(
            f'<tr><td class="{"ok" if ok else "bad"}">{"Quiet" if ok else "Fired"}</td>'
            f"<td>{escape(s.note)}</td><td><code>{escape(str(s.event.get('CommandLine', '')))}</code></td></tr>"
        )
    benign = (
        "<h4>Normal activity it must ignore</h4>"
        '<div class="table"><table><thead><tr><th>Result</th><th>Scenario</th><th>Command line</th></tr></thead>'
        f"<tbody>{''.join(rows)}</tbody></table></div>"
    )
    if r.attack:
        cap = r.capture or {}
        tests = ", ".join(str(t) for t in cap.get("tests", []))
        attack = (
            "<h4>Recorded attack it must catch</h4>"
            f"<p>Detected <strong>{len(r.tests_detected)} of {len(r.tests_run)}</strong> Atomic tests "
            f"({len(r.attack)} process events) recorded on "
            f"{escape(str(cap.get('host', 'the lab host')))} running Atomic Red Team "
            f"{escape(str(cap.get('technique', '')))} test {escape(tests)}, "
            f"captured {escape(str(cap.get('captured_utc', '')))} UTC.</p>"
        )
    else:
        attack = (
            "<h4>Recorded attack it must catch</h4>"
            "<p class=\"muted\">Not recorded yet. The rule only counts as proven once "
            "<code>scripts/capture.ps1</code> has recorded the real attack in the lab and "
            "the rule fires on every recorded test.</p>"
        )
    return attack + benign


def _queries(r: RuleResult) -> str:
    blocks = []
    for target in TARGETS:
        path = query_path(target, r.stem)
        text = path.read_text(encoding="utf-8").strip() if path.exists() else "(not generated)"
        blocks.append(
            f"<h5>{escape(target.label)}</h5><pre><code>{escape(text)}</code></pre>"
        )
    return "<h4>Ready-to-run queries</h4>" + "".join(blocks)


def _rule(r: RuleResult) -> str:
    techniques = " ".join(
        f'<a href="{_technique_url(t)}" rel="noopener">{t}</a>' for t in r.techniques
    )
    level = r.rule.level.name.lower() if r.rule.level else "n/a"
    description = escape(r.rule.description or "").replace("\n", " ")
    rel = r.path.relative_to(ROOT).as_posix()
    return f"""
<details class="rule" id="{r.stem}">
  <summary>
    <span class="title">{escape(r.rule.title)}</span>
    <span class="meta"><span class="platform">{_platform(r)}</span> {techniques} <span class="level {level}">{level}</span> {_badge(r.status)}</span>
  </summary>
  <div class="body">
    <p>{description}</p>
    <p class="links"><a href="{REPO_URL}/blob/main/{rel}">Sigma rule</a> ·
      <a href="{REPO_URL}/tree/main/evidence/{r.stem}">Evidence</a></p>
    {_evidence(r)}
    {_queries(r)}
  </div>
</details>"""


def render(results: list[RuleResult]) -> str:
    techniques = sorted({t for r in results for t in r.techniques})
    proven = sum(r.status == PROVEN for r in results)
    awaiting = sum(r.status == AWAITING for r in results)
    benign_total = sum(len(r.benign) for r in results)
    benign_quiet = benign_total - sum(r.noisy for r in results)
    rules = "".join(_rule(r) for r in results)
    platforms = sorted({_platform(r) for r in results}, key=lambda p: p != "Windows")
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Witness: detections that prove themselves</title>
<meta name="description" content="Open-source Sigma detection rules for Windows and Linux. Each rule is tested in CI against attacks recorded in a lab and against look-alike normal activity, then translated for Sentinel, Defender XDR and Splunk.">
<link rel="icon" href="favicon.svg" type="image/svg+xml">
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;700;800&family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css">
</head>
<body>
<header class="wrap top">
  <a class="brand" href="./"><img src="favicon.svg" alt="" width="28" height="28"> witness</a>
  <nav><a href="#coverage">Coverage</a><a href="#rules">Rules</a><a href="{REPO_URL}">GitHub</a></nav>
</header>
<main class="wrap">
  <section class="hero">
    <p class="eyebrow">Detection as code</p>
    <h1>Detections that have to <em>prove</em> themselves.</h1>
    <p class="lede">Every rule here is checked on every commit: it must catch an attack recorded in
      a Windows or Linux lab VM and stay quiet on look-alike normal activity. Rules that pass are translated
      for Microsoft Sentinel, Defender XDR and Splunk.</p>
  </section>

  <section class="stats" aria-label="Summary">
    <div><strong>{len(results)}</strong><span>rules for {" and ".join(platforms)}</span></div>
    <div><strong>{len(techniques)}</strong><span>ATT&amp;CK techniques</span></div>
    <div><strong>{proven}</strong><span>proven in the lab</span></div>
    <div><strong>{awaiting}</strong><span>awaiting lab capture</span></div>
    <div><strong>{benign_quiet}/{benign_total}</strong><span>normal events left alone</span></div>
  </section>

  <section class="how">
    <div><span>1</span><h2>Write the rule</h2><p>A Sigma rule, tagged with the ATT&amp;CK technique it covers and the false positives it was tuned against.</p></div>
    <div><span>2</span><h2>Record the evidence</h2><p>The attack is run with Atomic Red Team in an isolated lab VM and the Sysmon events it leaves are saved next to the rule.</p></div>
    <div><span>3</span><h2>Prove it in CI</h2><p>GitHub Actions replays the evidence through the rule. A missed attack or a noisy match fails the build.</p></div>
  </section>

  <section id="coverage">
    <h2 class="section">Coverage across ATT&amp;CK tactics</h2>
    <p class="legend"><span class="chip proven">Proven</span><span class="chip awaiting">Awaiting capture</span><span class="chip failing">Failing</span></p>
    <div class="matrix">{_matrix(results)}</div>
  </section>

  <section id="rules">
    <h2 class="section">Rules</h2>
    {rules}
  </section>
</main>
<footer class="wrap">
  <p>Built by <a href="https://raghav.kuinkel.com">Raghav Kuinkel</a>. Rules and evidence are open source on
    <a href="{REPO_URL}">GitHub</a>. Data: <a href="coverage.json">coverage.json</a>.</p>
</footer>
</body>
</html>
"""


def render_all(results: list[RuleResult]) -> dict:
    return {
        SITE_DIR / "index.html": render(results),
        SITE_DIR / "coverage.json": json.dumps(coverage(results), indent=2) + "\n",
    }
