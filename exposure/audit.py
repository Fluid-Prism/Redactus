"""audit.py — headless CLI. `python3 -m exposure.audit`.

Scans, prints findings worst-first, records the run to local history.
`--json` emits the same data for scripting; masked evidence is included
there too, since it never contains usable material.
"""
import argparse
import os

from . import store, warn_if_root
from .rules import RULES_BY_ID
from .scanner import DEFAULT_TIME_BUDGET_SECONDS, scan
from .scoring import by_severity, ranked, weighted_total

_SEVERITY_LABEL = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW"}


def run_audit(roots=None, time_budget=DEFAULT_TIME_BUDGET_SECONDS, progress=None,
              include_caches=False):
    report = scan(roots=roots, time_budget=time_budget, progress=progress,
                  include_caches=include_caches)
    store.record_scan(report, weighted_total(report.findings))
    return report


def _print_coverage(report):
    print(f"  Looked at {report.files_seen:,} files in {report.duration_seconds:.1f}s "
          f"({report.files_read:,} read for content).")
    if not report.coverage_is_partial:
        return
    print("\n  Coverage was not complete:")
    if report.stopped_early:
        print(f"    - {report.stop_reason}")
    if report.skipped_too_large:
        print(f"    - {report.skipped_too_large:,} file(s) skipped for being over the size limit")
    if report.skipped_unreadable:
        print(f"    - {report.skipped_unreadable:,} file(s) couldn't be read")
    if report.detector_errors:
        print(f"    - {report.detector_errors:,} file(s) hit an internal error while being checked")
    print("    Findings below are real. Absence of a finding is not proof of absence.")


def _print_report(report):
    findings = ranked(report.findings)
    counts = by_severity(findings)

    print()
    if findings:
        summary = ", ".join(f"{counts[s]} {s}" for s in ("critical", "high", "medium", "low")
                            if counts[s])
        print(f"  {len(findings)} finding(s): {summary}\n")
    else:
        print("  No findings in what could be read.\n")

    _print_coverage(report)
    if not findings:
        return
    print()

    for finding in findings:
        rule = RULES_BY_ID.get(finding.rule_id)
        title = rule.title if rule else finding.rule_id
        where = finding.display_path
        if finding.line_no:
            where += f":{finding.line_no}"
        print(f"  [{_SEVERITY_LABEL.get(finding.severity, finding.severity.upper()):8}] {title}")
        print(f"           {where}")
        print(f"           {finding.detail}  ({finding.confidence})")
        if finding.evidence:
            print(f"           {finding.evidence}")
        if rule:
            fix = rule.remediation(finding)
            print("           Fix:")
            for line in fix.splitlines():
                print(f"             {line}")
        print()


def main(argv=None):
    warn_if_root()
    parser = argparse.ArgumentParser(
        description="Find credentials sitting unprotected in your home directory.")
    parser.add_argument("--path", action="append", dest="paths", metavar="DIR",
                        help="Directory to scan (repeatable). Defaults to your home directory.")
    parser.add_argument("--time-budget", type=float, default=DEFAULT_TIME_BUDGET_SECONDS,
                        metavar="SECONDS",
                        help=f"Stop scanning after this long (default {DEFAULT_TIME_BUDGET_SECONDS:.0f}).")
    parser.add_argument("--include-caches", action="store_true",
                        help="Also scan package caches, editor extensions and tool state "
                             "directories. Slower, and most of what it finds belongs to "
                             "software you installed rather than to you.")
    parser.add_argument("--json", action="store_true",
                        help="Emit findings as JSON instead of a report.")
    parser.add_argument("--forget", action="store_true",
                        help="Delete the local scan-history database and exit.")
    args = parser.parse_args(argv)

    if args.forget:
        store.forget_everything()
        print(f"Deleted {store.DB_PATH}")
        return 0

    roots = [os.path.abspath(os.path.expanduser(p)) for p in args.paths] if args.paths else None
    report = run_audit(roots=roots, time_budget=args.time_budget,
                       include_caches=args.include_caches)

    if args.json:
        import json
        print(json.dumps({
            "roots": report.roots,
            "files_seen": report.files_seen,
            "files_read": report.files_read,
            "coverage_is_partial": report.coverage_is_partial,
            "stopped_early": report.stopped_early,
            "stop_reason": report.stop_reason,
            "skipped_too_large": report.skipped_too_large,
            "skipped_unreadable": report.skipped_unreadable,
            "counts": by_severity(report.findings),
            "findings": [
                {"rule_id": f.rule_id, "severity": f.severity, "path": f.display_path,
                 "detail": f.detail, "confidence": f.confidence,
                 "evidence": f.evidence, "line": f.line_no}
                for f in ranked(report.findings)
            ],
        }, indent=2))
    else:
        _print_report(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
