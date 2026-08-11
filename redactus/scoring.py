"""scoring.py — organise findings without inventing a number.

There is deliberately no 0-100 "exposure score" here, which is a departure
from how this tool's sibling projects report. A posture score works because
its denominator is fixed and known: a set list of checks, each of which
passes or fails. Findings have no denominator. Zero findings doesn't mean
zero exposure — it means nothing matched the rules that exist, in the files
that were readable, in the time available. Compressing that into "94/100"
would be inventing precision the data doesn't have, and the number people
would remember is exactly the one that isn't true.

So what comes out is a count per severity, ranked, with the coverage gaps
attached. "3 critical, 11 high, and here's what I couldn't read" is a
smaller claim than a score, and it's one this tool can actually support.
"""
from .rules.base import CONFIDENCE_ORDER, SEVERITY_ORDER, SEVERITY_WEIGHT


def by_severity(findings):
    """{'critical': 3, 'high': 11, ...} — every severity present, zeroes included,
    so a caller rendering this doesn't have to guess which keys exist."""
    counts = {severity: 0 for severity in SEVERITY_ORDER}
    for finding in findings:
        if finding.severity in counts:
            counts[finding.severity] += 1
    return counts


def ranked(findings):
    """Most urgent first: severity, then confidence, then path for stability.

    Confidence breaks the severity tie on purpose — given two `high`
    findings, the one that's a verified fact belongs above the one that's a
    pattern match, because that's the order someone should spend attention in.
    """
    def sort_key(finding):
        severity_rank = SEVERITY_ORDER.index(finding.severity) if finding.severity in SEVERITY_ORDER else 99
        confidence_rank = (CONFIDENCE_ORDER.index(finding.confidence)
                           if finding.confidence in CONFIDENCE_ORDER else 99)
        return (severity_rank, confidence_rank, finding.display_path, finding.rule_id)
    return sorted(findings, key=sort_key)


def worst_severity(findings):
    """The single most severe thing found, or None. Used for the headline."""
    for severity in SEVERITY_ORDER:
        if any(f.severity == severity for f in findings):
            return severity
    return None


def weighted_total(findings):
    """A relative measure for comparing one scan against the next on the same
    machine. Not a score, not a percentage, and not comparable between
    machines — only useful as 'is this going up or down for me'."""
    return sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)


def group_by_file(findings):
    """[(display_path, [findings...]), ...] with the worst files first — the
    unit people actually act on is a file, not an individual match."""
    grouped = {}
    for finding in findings:
        grouped.setdefault(finding.display_path, []).append(finding)
    return sorted(grouped.items(),
                  key=lambda item: (-weighted_total(item[1]), item[0]))
