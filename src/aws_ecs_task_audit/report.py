"""Rendering of findings as a grouped text table or as JSON."""

from __future__ import annotations

import json
import textwrap
from collections.abc import Iterable
from typing import Any

from .rules import SEVERITIES, Finding

SEVERITY_LABEL = {"high": "HIGH", "medium": "MED ", "low": "LOW "}


def _group(findings: Iterable[Finding]) -> list[tuple[tuple[str, int], list[Finding]]]:
    grouped: dict[tuple[str, int], list[Finding]] = {}
    for finding in findings:
        grouped.setdefault((finding.family, finding.revision), []).append(finding)
    return sorted(grouped.items())


def counts_by_severity(findings: Iterable[Finding]) -> dict[str, int]:
    counts = {severity: 0 for severity in SEVERITIES}
    for finding in findings:
        counts[finding.severity] += 1
    return counts


def render_text(findings: list[Finding], payload: dict[str, Any], width: int = 100) -> str:
    scanned = len(payload.get("task_definitions") or [])
    lines: list[str] = []

    if not findings:
        lines.append(f"No findings across {scanned} task definition(s).")
        return "\n".join(lines)

    for (family, revision), group in _group(findings):
        lines.append(f"{family}:{revision}")
        for finding in group:
            target = finding.container or "task"
            head = f"  {SEVERITY_LABEL[finding.severity]} {finding.rule:<22} {target}"
            lines.append(head)
            body = textwrap.wrap(finding.message, width=max(40, width - 8))
            lines.extend(f"        {line}" for line in body)
        lines.append("")

    counts = counts_by_severity(findings)
    lines.append(
        f"{len(findings)} finding(s) across {scanned} task definition(s): "
        f"{counts['high']} high, {counts['medium']} medium, {counts['low']} low."
    )
    return "\n".join(lines)


def render_json(findings: list[Finding], payload: dict[str, Any]) -> str:
    document = {
        "region": payload.get("region"),
        "collected_at": payload.get("collected_at"),
        "task_definitions_scanned": len(payload.get("task_definitions") or []),
        "counts": counts_by_severity(findings),
        "findings": [finding.to_dict() for finding in findings],
    }
    return json.dumps(document, indent=2, sort_keys=False)
