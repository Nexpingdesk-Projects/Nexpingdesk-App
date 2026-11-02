#!/usr/bin/env python3
"""Security alerts for a private repository, as GitHub issues.

GitHub's code-scanning and secret-scanning alert lists aren't available to a
private repository on a Free-plan organization, so .github/workflows/
security-alerts.yml runs the scanners itself and this script mirrors their
findings into issues labelled "security-alert", with the same lifecycle:

  new finding            → issue opened (one per finding)
  finding gone           → issue closed as completed ("fixed")
  finding back           → closed-as-completed issue reopened
  issue closed as
  "not planned"          → dismissed: never reopened, like dismissing an alert

Each issue carries a stable id in a hidden marker, so moving code around
doesn't churn issues. Inputs are the scanners' JSON reports; any may be
missing or empty. Secrets are never copied into issues (gitleaks runs with
--redact and only its rule, file and commit are shown).

  scripts/security-alerts.py --semgrep s.json --gitleaks g.json \\
      --composer [DIR=]c.json … --npm [DIR=]n.json … [--dry-run]

--composer and --npm repeat, one per package folder (DIR, default the root).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

LABEL = "security-alert"
MARKER = re.compile(r"<!-- security-alert-id: (\S+) -->")
SEVERITY_ORDER = {"critical": 0, "high": 1, "error": 1, "moderate": 2, "medium": 2, "warning": 2, "low": 3, "info": 4}


def load(path: str | None):
    if not path or not Path(path).is_file() or Path(path).stat().st_size == 0:
        return None
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def digest(*parts: str) -> str:
    # nosemgrep: python.lang.security.insecure-hash-algorithms.insecure-hash-algorithm-sha1 -- an issue fingerprint, not a security hash; changing it would orphan every open alert issue
    return hashlib.sha1("\x1f".join(parts).encode()).hexdigest()[:16]


def semgrep_findings(report) -> list[dict]:
    out = []
    for r in (report or {}).get("results", []):
        extra = r.get("extra", {})
        rule = r["check_id"]
        # Rule + file + the matched code (whitespace-normalised), not the line
        # number: an unrelated edit above the finding must not reopen it.
        code = " ".join(str(extra.get("lines", "")).split())
        out.append({
            "id": "semgrep-" + digest(rule, r["path"], code),
            "tool": "Code scanning (Semgrep)",
            "severity": str(extra.get("severity", "warning")).lower(),
            "title": f"{rule.rsplit('.', 1)[-1]} in {r['path']}",
            "detail": (
                f"**Rule:** `{rule}`\n**Location:** `{r['path']}:{r['start']['line']}`\n\n"
                f"{extra.get('message', '').strip()}\n\n"
                "Fix it, or — if it's a false positive — add "
                f"`// nosemgrep: {rule} -- <why>` on that line and close this issue as *not planned*."
            ),
        })
    return out


def gitleaks_findings(report) -> list[dict]:
    out = []
    for f in report or []:
        out.append({
            "id": "secret-" + digest(f.get("Fingerprint") or f"{f.get('Commit')}:{f.get('File')}:{f.get('RuleID')}"),
            "tool": "Secret scanning (gitleaks)",
            "severity": "critical",
            "title": f"{f.get('RuleID', 'secret')} in {f.get('File', '?')}",
            "detail": (
                f"**Rule:** `{f.get('RuleID')}` — {f.get('Description', '')}\n"
                f"**Location:** `{f.get('File')}:{f.get('StartLine')}` (commit `{str(f.get('Commit', ''))[:12]}`)\n\n"
                "**Revoke/rotate this credential first** — it is in the git history, so deleting the "
                "file doesn't un-leak it. Then remove it from the code and keep it in a secret store "
                "(a GitHub Environment secret, or the server's `.env`)."
            ),
        })
    return out


def where(package_dir: str) -> tuple[tuple[str, ...], str]:
    """Id parts and title prefix for a package folder; the root keeps the original ids."""
    return ((), "") if package_dir in ("", ".") else ((package_dir,), f"{package_dir}/")


def composer_findings(package_dir: str, report) -> list[dict]:
    key, prefix = where(package_dir)
    advisories = (report or {}).get("advisories") or {}
    if isinstance(advisories, list):  # composer prints [] when there are none
        advisories = {}
    out = []
    for package, items in advisories.items():
        for a in items:
            out.append({
                "id": "composer-" + digest(*key, package, str(a.get("advisoryId"))),
                "tool": "Dependency advisory (Composer)",
                "severity": str(a.get("severity") or "high").lower(),
                "title": f"{prefix}{package}: {a.get('title', 'security advisory')}",
                "detail": (
                    f"**Package:** `{package}` — affected `{a.get('affectedVersions', '?')}`\n"
                    f"**Advisory:** {a.get('cve') or a.get('advisoryId')} — {a.get('link', '')}\n\n"
                    "Update it (`composer update " + package + " --with-dependencies`) or wait for the "
                    "Dependabot security PR."
                ),
            })
    return out


def npm_allowed() -> set[str]:
    """Advisories CI accepts (NPM_AUDIT_DEV_ALLOW in ci.yml): one list, not two."""
    value = os.environ.get("NPM_AUDIT_DEV_ALLOW")
    if value is None:
        ci = Path(__file__).resolve().parent.parent / ".github/workflows/ci.yml"
        m = re.search(r"^\s*NPM_AUDIT_DEV_ALLOW:\s*(.+)$", ci.read_text(encoding="utf-8"), re.M) if ci.is_file() else None
        value = m.group(1).strip().strip("\"'") if m else ""
    return set(value.split())


def npm_findings(package_dir: str, report) -> list[dict]:
    key, prefix = where(package_dir)
    allowed = npm_allowed()
    out = []
    for name, v in ((report or {}).get("vulnerabilities") or {}).items():
        # Only the package an advisory is filed against: npm also lists every
        # package that depends on it (one braces advisory became 22 issues).
        via = [
            x for x in v.get("via", [])
            if isinstance(x, dict) and str(x.get("url", "")).rsplit("/", 1)[-1] not in allowed
        ]
        if not via:
            continue
        sources = sorted(str(x.get("source")) for x in via)
        titles = sorted({x.get("title", "") for x in via})
        out.append({
            "id": "npm-" + digest(*key, name, ",".join(sources) or v.get("range", "")),
            "tool": "Dependency advisory (npm)",
            "severity": str(v.get("severity", "moderate")).lower(),
            "title": f"{prefix}{name}: {'; '.join(t for t in titles if t) or 'vulnerable dependency'}",
            "detail": f"**Package:** `{name}` — affected `{v.get('range', '?')}`\n\nRun `npm audit fix` or wait for the Dependabot PR.",
        })
    return out


def gh(*args: str) -> str:
    return subprocess.run(["gh", *args], check=True, capture_output=True, text=True).stdout


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--semgrep")
    ap.add_argument("--gitleaks")
    ap.add_argument("--composer", action="append", default=[], metavar="[DIR=]REPORT",
                    help="composer audit --format=json report (repeatable, one per package folder)")
    ap.add_argument("--npm", action="append", default=[], metavar="[DIR=]REPORT",
                    help="npm audit --json report (repeatable, one per package folder)")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    findings = semgrep_findings(load(args.semgrep)) + gitleaks_findings(load(args.gitleaks))
    for kind, specs in ((composer_findings, args.composer), (npm_findings, args.npm)):
        for spec in specs:
            package_dir, _, report = spec.rpartition("=")
            findings += kind(package_dir or ".", load(report))
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f["severity"], 5), f["title"]))
    current = {f["id"]: f for f in findings}
    print(f"{len(findings)} finding(s)")
    for f in findings:
        print(f"  [{f['severity']}] {f['tool']}: {f['title']}")

    if args.dry_run:
        return 0

    sha = os.environ.get("GITHUB_SHA", "")[:12]
    run = os.environ.get("RUN_URL", "")
    # REST, not `gh issue list`: only the API exposes state_reason, which is
    # what tells "fixed" (completed) apart from "dismissed" (not_planned).
    lines = gh("api", "--paginate", f"repos/{{owner}}/{{repo}}/issues?labels={LABEL}&state=all&per_page=100",
               "--jq", ".[] | select(.pull_request | not) | {number, state, state_reason, body}")
    known = {}
    for line in lines.splitlines():
        i = json.loads(line)
        m = MARKER.search(i.get("body") or "")
        if not m:
            continue
        fid = m.group(1)
        # The label index lags issue creation by a few seconds, so two scans
        # in quick succession can both open one: keep the oldest, close the rest.
        if fid in known:
            keep, extra = sorted([known[fid], i], key=lambda x: x["number"])
            if extra["state"] == "open":
                gh("issue", "close", str(extra["number"]), "--reason", "not planned",
                   "--comment", f"Duplicate of #{keep['number']}.")
            known[fid] = keep
        else:
            known[fid] = i

    for fid, f in current.items():
        issue = known.get(fid)
        if issue is None:
            body = (f"{f['detail']}\n\n---\nFound by **{f['tool']}** on `{sha}`. {run}\n"
                    f"Closes itself once a scan no longer reports it.\n\n<!-- security-alert-id: {fid} -->")
            gh("issue", "create", "--title", f"[{f['severity'].upper()}] {f['title']}"[:250],
               "--label", LABEL, "--body", body)
            print(f"opened: {f['title']}")
        elif issue["state"] == "closed" and issue.get("state_reason") != "not_planned":
            gh("issue", "reopen", str(issue["number"]))
            gh("issue", "comment", str(issue["number"]), "--body", f"Reported again by the scan of `{sha}`. {run}")
            print(f"reopened #{issue['number']}")

    for fid, issue in known.items():
        if fid not in current and issue["state"] == "open":
            gh("issue", "close", str(issue["number"]), "--reason", "completed",
               "--comment", f"Fixed — no longer reported by the scan of `{sha}`. {run}")
            print(f"closed #{issue['number']}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
