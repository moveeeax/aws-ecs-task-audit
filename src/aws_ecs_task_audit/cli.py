"""Command line entry point.

Exit codes
----------
0   no finding matched ``--fail-on`` (or ``--fail-on`` was not given)
1   at least one finding matched ``--fail-on``
2   usage error: unknown rule or severity name, unreadable input, AWS failure
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence

from . import __version__
from .collector import CollectionError, collect, dump, load
from .report import render_json, render_text
from .rules import RULES, SEVERITIES, UnknownRuleError, audit, validate_rule_names

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2


def _split(values: Sequence[str] | None) -> list[str]:
    out: list[str] = []
    for value in values or []:
        out.extend(part.strip() for part in value.split(",") if part.strip())
    return out


def build_parser() -> argparse.ArgumentParser:
    rule_help = "\n".join(f"  {rule.name:<22} {rule.summary}" for rule in RULES)
    parser = argparse.ArgumentParser(
        prog="aws-ecs-task-audit",
        description="Audit ECS task definitions for the structural mistakes nobody reviews.",
        epilog="rules:\n" + rule_help,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    source = parser.add_argument_group("source")
    source.add_argument("--profile", help="AWS profile to collect with")
    source.add_argument("--region", help="AWS region to collect from")
    source.add_argument(
        "--all-revisions",
        action="store_true",
        help="describe every ACTIVE revision, not just the latest of each family",
    )
    source.add_argument(
        "--family",
        action="append",
        default=[],
        metavar="NAME",
        help="limit collection to this family (repeatable)",
    )
    source.add_argument(
        "--from-json",
        metavar="FILE",
        help="replay a payload written by --dump-json instead of calling AWS",
    )
    source.add_argument(
        "--dump-json",
        metavar="FILE",
        help="write the collected payload to FILE for offline replay",
    )

    output = parser.add_argument_group("output")
    output.add_argument("--format", choices=("text", "json"), default="text")
    output.add_argument(
        "--severity",
        choices=SEVERITIES,
        default="low",
        help="suppress findings below this severity (default: low)",
    )
    output.add_argument(
        "--ignore-rule",
        action="append",
        default=[],
        metavar="RULES",
        help="comma separated rule names to skip (repeatable)",
    )
    output.add_argument(
        "--ignore-family",
        action="append",
        default=[],
        metavar="FAMILIES",
        help="comma separated task definition families to skip (repeatable)",
    )
    output.add_argument(
        "--fail-on",
        action="append",
        default=[],
        metavar="RULES",
        help="comma separated rule names that make the run exit 1",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    ignore_rules = _split(args.ignore_rule)
    ignore_families = _split(args.ignore_family)
    fail_on = _split(args.fail_on)

    try:
        validate_rule_names(ignore_rules)
        validate_rule_names(fail_on)
    except UnknownRuleError as exc:
        print(f"aws-ecs-task-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE

    try:
        if args.from_json:
            payload = load(args.from_json)
        else:
            payload = collect(
                profile=args.profile,
                region=args.region,
                all_revisions=args.all_revisions,
                families=args.family or None,
            )
    except CollectionError as exc:
        print(f"aws-ecs-task-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except OSError as exc:
        print(f"aws-ecs-task-audit: {exc}", file=sys.stderr)
        return EXIT_USAGE
    except Exception as exc:  # botocore errors are many and not worth enumerating
        print(f"aws-ecs-task-audit: collection failed: {exc}", file=sys.stderr)
        return EXIT_USAGE

    if args.dump_json:
        try:
            dump(payload, args.dump_json)
        except OSError as exc:
            print(f"aws-ecs-task-audit: {exc}", file=sys.stderr)
            return EXIT_USAGE

    findings = audit(
        payload,
        ignore_rules=ignore_rules,
        ignore_families=ignore_families,
        min_severity=args.severity,
    )

    if args.format == "json":
        print(render_json(findings, payload))
    else:
        print(render_text(findings, payload))

    if fail_on and any(finding.rule in fail_on for finding in findings):
        return EXIT_FINDINGS
    return EXIT_OK


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
