"""The rule engine.

Every rule is a pure function of a single task definition dict. No network, no
clock, no environment — which is what makes the fixtures under ``tests/fixtures``
a complete test harness for the tool.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Callable

SEVERITIES = ("low", "medium", "high")

#: Supported Fargate cpu -> (min memory, max memory, step) combinations.
#: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/task-cpu-memory-error.html
FARGATE_CPU_MEMORY: dict[int, tuple[int, int, int]] = {
    256: (512, 2048, 0),  # 512, 1024, 2048 — handled as an explicit set below
    512: (1024, 4096, 1024),
    1024: (2048, 8192, 1024),
    2048: (4096, 16384, 1024),
    4096: (8192, 30720, 1024),
    8192: (16384, 61440, 4096),
    16384: (32768, 122880, 8192),
}

_CPU_256_MEMORY = (512, 1024, 2048)

#: Environment variable names that carry a credential often enough to be worth
#: a finding. Matched case-insensitively as substrings.
SECRET_NAME_PATTERNS = (
    "PASSWORD",
    "PASSWD",
    "SECRET",
    "TOKEN",
    "APIKEY",
    "API_KEY",
    "ACCESS_KEY",
    "PRIVATE_KEY",
    "CREDENTIAL",
    "CONNECTION_STRING",
    "_DSN",
    "DSN_",
)

#: Names that look credential-shaped but are routinely plain identifiers.
SECRET_NAME_ALLOWLIST = (
    "PUBLIC_KEY",
    "PARTITION_KEY",
    "SORT_KEY",
    "IDEMPOTENCY_KEY",
    "KEY_NAME",
    "KEY_PREFIX",
    "KEY_PATH",
    "KEY_FILE",
    "TOKEN_URL",
    "TOKEN_ENDPOINT",
    "SECRET_NAME",
    "SECRET_ARN",
    "SECRET_ID",
)

_AWS_KEY_ID = re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")
_URL_WITH_CREDS = re.compile(r"[a-z][a-z0-9+.-]*://[^/\s:@]+:[^/\s@]+@", re.IGNORECASE)
_PEM_HEADER = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")

#: Tags that move under you. A restart picks up a different image and nothing
#: in the task definition records that it happened.
MOVING_TAGS = ("latest", "stable", "main", "master", "edge", "prod", "production", "dev", "test")


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    family: str
    revision: int
    message: str
    container: str | None = None
    task_definition_arn: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule": self.rule,
            "severity": self.severity,
            "family": self.family,
            "revision": self.revision,
            "container": self.container,
            "task_definition_arn": self.task_definition_arn,
            "message": self.message,
        }


@dataclass
class Rule:
    name: str
    severity: str
    summary: str
    check: Callable[[TaskContext], list[Finding]] = field(repr=False)


@dataclass
class TaskContext:
    """A task definition plus the few derived facts every rule wants."""

    definition: dict[str, Any]

    @property
    def family(self) -> str:
        return self.definition.get("family") or "<unknown>"

    @property
    def revision(self) -> int:
        try:
            return int(self.definition.get("revision", 0))
        except (TypeError, ValueError):
            return 0

    @property
    def arn(self) -> str | None:
        return self.definition.get("taskDefinitionArn")

    @property
    def containers(self) -> list[dict[str, Any]]:
        return list(self.definition.get("containerDefinitions") or [])

    @property
    def compatibilities(self) -> list[str]:
        raw = self.definition.get("requiresCompatibilities") or []
        return [str(x).upper() for x in raw]

    @property
    def is_fargate(self) -> bool:
        return "FARGATE" in self.compatibilities

    @property
    def is_ec2(self) -> bool:
        # An empty requiresCompatibilities means EC2: that is the API default.
        return "EC2" in self.compatibilities or not self.compatibilities

    @property
    def network_mode(self) -> str:
        return str(self.definition.get("networkMode") or "bridge").lower()

    def finding(self, rule: str, severity: str, message: str, container: str | None = None) -> Finding:
        return Finding(
            rule=rule,
            severity=severity,
            family=self.family,
            revision=self.revision,
            container=container,
            task_definition_arn=self.arn,
            message=message,
        )


def _name(container: dict[str, Any]) -> str:
    return container.get("name") or "<unnamed>"


def _essential(container: dict[str, Any]) -> bool:
    # The API default for essential is true.
    return container.get("essential", True) is not False


# --------------------------------------------------------------------------- #
# rule implementations
# --------------------------------------------------------------------------- #


def _looks_like_secret_name(name: str) -> bool:
    upper = name.upper()
    if any(allowed in upper for allowed in SECRET_NAME_ALLOWLIST):
        return False
    return any(pattern in upper for pattern in SECRET_NAME_PATTERNS)


def _looks_like_secret_value(value: str) -> bool:
    if not value or len(value) < 20:
        return False
    if _AWS_KEY_ID.search(value):
        return True
    if _URL_WITH_CREDS.search(value):
        return True
    if _PEM_HEADER.search(value):
        return True
    return False


def check_plaintext_secret(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        for entry in container.get("environment") or []:
            name = str(entry.get("name") or "")
            value = str(entry.get("value") or "")
            if _looks_like_secret_name(name):
                reason = f"environment variable {name} is named like a credential"
            elif _looks_like_secret_value(value):
                reason = f"environment variable {name} holds a value shaped like a credential"
            else:
                continue
            findings.append(
                ctx.finding(
                    "plaintext-secret",
                    "high",
                    f"{reason}; anyone who can call DescribeTaskDefinition can read it. "
                    "Move it to the secrets block and reference Secrets Manager or SSM.",
                    container=_name(container),
                )
            )
    return findings


def _parse_image(image: str) -> tuple[str, str | None, str | None]:
    """Split an image reference into (repository, tag, digest)."""
    digest = None
    rest = image
    if "@" in image:
        rest, digest = image.split("@", 1)
    tag = None
    # A colon in the registry host (host:5000/repo) is not a tag separator.
    last_slash = rest.rfind("/")
    tail = rest[last_slash + 1 :]
    if ":" in tail:
        name_part, tag = tail.rsplit(":", 1)
        rest = rest[: last_slash + 1] + name_part
    return rest, tag, digest


def check_mutable_image_tag(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        image = str(container.get("image") or "")
        if not image:
            findings.append(
                ctx.finding(
                    "mutable-image-tag",
                    "medium",
                    "container has no image reference at all",
                    container=_name(container),
                )
            )
            continue
        repo, tag, digest = _parse_image(image)
        if digest:
            continue  # a digest pins the build no matter what tag rides along
        if tag is None:
            detail = f"{repo} has no tag, so it resolves to :latest"
        elif tag.lower() in MOVING_TAGS:
            detail = f"{repo}:{tag} is a moving tag"
        else:
            continue
        findings.append(
            ctx.finding(
                "mutable-image-tag",
                "medium",
                f"{detail}; a task restart can ship a different build with no change here. "
                "Pin a digest or an immutable version tag.",
                container=_name(container),
            )
        )
    return findings


def check_no_logging(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        if not container.get("logConfiguration"):
            findings.append(
                ctx.finding(
                    "no-logging",
                    "medium",
                    "no logConfiguration, so container output is unreachable once the task stops",
                    container=_name(container),
                )
            )
    return findings


def check_no_healthcheck(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        if _essential(container) and not container.get("healthCheck"):
            findings.append(
                ctx.finding(
                    "no-healthcheck",
                    "low",
                    "essential container has no healthCheck, so a wedged process keeps its "
                    "task registered until something downstream notices",
                    container=_name(container),
                )
            )
    return findings


def check_root_user(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        user = str(container.get("user") or "").strip()
        normalized = user.split(":", 1)[0].lower()
        if user == "" or normalized in ("0", "root"):
            detail = "user is unset" if user == "" else f"user is {user}"
            findings.append(
                ctx.finding(
                    "root-user",
                    "medium",
                    f"{detail}, so the container runs as root",
                    container=_name(container),
                )
            )
    return findings


def check_writable_root_fs(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        if container.get("readonlyRootFilesystem") is not True:
            findings.append(
                ctx.finding(
                    "writable-root-fs",
                    "low",
                    "readonlyRootFilesystem is not set, so anything in the container can "
                    "write to the image filesystem",
                    container=_name(container),
                )
            )
    return findings


def _valid_fargate_memory(cpu: int) -> list[int]:
    if cpu == 256:
        return list(_CPU_256_MEMORY)
    if cpu not in FARGATE_CPU_MEMORY:
        return []
    low, high, step = FARGATE_CPU_MEMORY[cpu]
    return list(range(low, high + 1, step))


def _nearest_valid_pair(cpu: int, memory: int) -> tuple[int, int]:
    """The supported (cpu, memory) pair closest to what was asked for.

    Preference goes to a pair that holds at least the requested memory, because
    shrinking memory to make a task registrable is how you get an OOM kill.
    """
    candidates: list[tuple[int, int]] = []
    for candidate_cpu in sorted(FARGATE_CPU_MEMORY):
        for candidate_memory in _valid_fargate_memory(candidate_cpu):
            candidates.append((candidate_cpu, candidate_memory))

    fits = [c for c in candidates if c[0] >= cpu and c[1] >= memory]
    pool = fits or candidates
    return min(pool, key=lambda c: (c[0] - cpu) ** 2 + ((c[1] - memory) / 1024.0) ** 2)


def check_invalid_fargate_size(ctx: TaskContext) -> list[Finding]:
    if not ctx.is_fargate:
        return []
    raw_cpu = ctx.definition.get("cpu")
    raw_memory = ctx.definition.get("memory")
    if raw_cpu is None or raw_memory is None:
        return [
            ctx.finding(
                "invalid-fargate-size",
                "high",
                "FARGATE task definition without task-level cpu and memory; "
                "RunTask rejects it at launch time, not at registration",
            )
        ]
    try:
        cpu = int(str(raw_cpu))
        memory = int(str(raw_memory))
    except ValueError:
        return [
            ctx.finding(
                "invalid-fargate-size",
                "high",
                f"cpu={raw_cpu!r} memory={raw_memory!r} are not integers",
            )
        ]

    if memory in _valid_fargate_memory(cpu):
        return []

    best_cpu, best_memory = _nearest_valid_pair(cpu, memory)
    return [
        ctx.finding(
            "invalid-fargate-size",
            "high",
            f"cpu {cpu} with memory {memory} is not a supported Fargate combination; "
            f"RunTask fails at launch time, not at registration. "
            f"Nearest supported pair is cpu {best_cpu} with memory {best_memory}.",
        )
    ]


def check_missing_task_role(ctx: TaskContext) -> list[Finding]:
    task_role = ctx.definition.get("taskRoleArn")
    execution_role = ctx.definition.get("executionRoleArn")
    if not task_role:
        return [
            ctx.finding(
                "missing-task-role",
                "medium",
                "taskRoleArn is absent, so the application has no identity of its own and any "
                "AWS call it makes falls back to the instance or execution credentials",
            )
        ]
    if execution_role and task_role == execution_role:
        return [
            ctx.finding(
                "missing-task-role",
                "medium",
                f"taskRoleArn is the same role as executionRoleArn ({task_role}); the agent's "
                "ECR pull and log-write permissions are handed to the application, collapsing "
                "two trust boundaries into one",
            )
        ]
    return []


def check_unbounded_container(ctx: TaskContext) -> list[Finding]:
    if ctx.is_fargate and not ctx.is_ec2:
        return []  # task-level memory is mandatory and bounds every container
    if ctx.definition.get("memory"):
        return []  # a task-level cap bounds the whole task on EC2 too
    findings: list[Finding] = []
    for container in ctx.containers:
        if not container.get("memory") and not container.get("memoryReservation"):
            findings.append(
                ctx.finding(
                    "unbounded-container",
                    "medium",
                    "no memory and no memoryReservation on an EC2 launch type container, so one "
                    "leak evicts its neighbours on the same instance",
                    container=_name(container),
                )
            )
    return findings


def check_privileged(ctx: TaskContext) -> list[Finding]:
    findings: list[Finding] = []
    for container in ctx.containers:
        if container.get("privileged") is True:
            findings.append(
                ctx.finding(
                    "privileged",
                    "high",
                    "privileged: true gives the container the host's device access and "
                    "effectively the host itself",
                    container=_name(container),
                )
            )
    return findings


def check_host_network(ctx: TaskContext) -> list[Finding]:
    if ctx.network_mode != "host":
        return []
    findings: list[Finding] = []
    for container in ctx.containers:
        ports = [
            m.get("hostPort", m.get("containerPort"))
            for m in container.get("portMappings") or []
        ]
        ports = [p for p in ports if p is not None]
        if not ports:
            continue
        listed = ", ".join(str(p) for p in ports)
        findings.append(
            ctx.finding(
                "host-network",
                "high",
                f"networkMode host binds {listed} directly on the instance; a second task of "
                "this family cannot be placed there and the port bypasses the task's own "
                "security group",
                container=_name(container),
            )
        )
    return findings


RULES: tuple[Rule, ...] = (
    Rule("plaintext-secret", "high", "credential sitting in environment instead of secrets", check_plaintext_secret),
    Rule("mutable-image-tag", "medium", "image reference that can change under a restart", check_mutable_image_tag),
    Rule("no-logging", "medium", "container output goes nowhere", check_no_logging),
    Rule("no-healthcheck", "low", "essential container with no healthCheck", check_no_healthcheck),
    Rule("root-user", "medium", "container runs as root", check_root_user),
    Rule("writable-root-fs", "low", "image filesystem is writable at runtime", check_writable_root_fs),
    Rule("invalid-fargate-size", "high", "cpu/memory pair Fargate will refuse", check_invalid_fargate_size),
    Rule("missing-task-role", "medium", "no task role, or the execution role doing both jobs", check_missing_task_role),
    Rule("unbounded-container", "medium", "EC2 container with no memory limit", check_unbounded_container),
    Rule("privileged", "high", "privileged container", check_privileged),
    Rule("host-network", "high", "host networkMode with published ports", check_host_network),
)

RULES_BY_NAME: dict[str, Rule] = {rule.name: rule for rule in RULES}


class UnknownRuleError(ValueError):
    """Raised for a rule name that does not exist."""

    def __init__(self, names: list[str]):
        self.names = names
        known = ", ".join(sorted(RULES_BY_NAME))
        plural = "s" if len(names) > 1 else ""
        super().__init__(
            f"unknown rule name{plural}: {', '.join(names)}. Known rules: {known}"
        )


def validate_rule_names(names: list[str]) -> list[str]:
    unknown = [n for n in names if n not in RULES_BY_NAME]
    if unknown:
        raise UnknownRuleError(unknown)
    return names


def audit(
    payload: dict[str, Any],
    ignore_rules: list[str] | None = None,
    ignore_families: list[str] | None = None,
    min_severity: str = "low",
) -> list[Finding]:
    """Run every enabled rule over every task definition in ``payload``."""
    ignore_rules = ignore_rules or []
    ignore_families = ignore_families or []
    validate_rule_names(ignore_rules)
    if min_severity not in SEVERITIES:
        raise ValueError(
            f"unknown severity: {min_severity}. Known severities: {', '.join(SEVERITIES)}"
        )
    floor = SEVERITIES.index(min_severity)

    findings: list[Finding] = []
    for definition in payload.get("task_definitions") or []:
        ctx = TaskContext(definition)
        if ctx.family in ignore_families:
            continue
        for rule in RULES:
            if rule.name in ignore_rules:
                continue
            for finding in rule.check(ctx):
                if SEVERITIES.index(finding.severity) >= floor:
                    findings.append(finding)

    findings.sort(
        key=lambda f: (
            f.family,
            f.revision,
            -SEVERITIES.index(f.severity),
            f.rule,
            f.container or "",
        )
    )
    return findings
