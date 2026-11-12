"""Collection of ECS task definitions.

The collector is deliberately thin: it talks to the ECS API and returns a plain
dict. Every rule in :mod:`aws_ecs_task_audit.rules` consumes that dict and
nothing else, which is why the whole rule suite runs offline against JSON
fixtures and CI needs no AWS credentials.
"""

from __future__ import annotations

import datetime as _dt
import json
import re
from collections.abc import Iterable
from pathlib import Path
from typing import Any

from . import SCHEMA_VERSION


class CollectionError(RuntimeError):
    """Raised when a payload cannot be collected or replayed."""


def _utcnow() -> str:
    return _dt.datetime.now(_dt.UTC).replace(microsecond=0).isoformat()


def _session(profile: str | None, region: str | None):
    try:
        import boto3  # imported lazily so offline replays need no boto3
    except ImportError as exc:  # pragma: no cover - exercised only without boto3
        raise CollectionError(
            "boto3 is required for live collection; install it or use --from-json"
        ) from exc
    kwargs: dict[str, Any] = {}
    if profile:
        kwargs["profile_name"] = profile
    if region:
        kwargs["region_name"] = region
    return boto3.session.Session(**kwargs)


def _families(client) -> list[str]:
    families: list[str] = []
    paginator = client.get_paginator("list_task_definition_families")
    for page in paginator.paginate(status="ACTIVE"):
        families.extend(page.get("families", []))
    return families


def _revision_arns(client, family: str) -> list[str]:
    arns: list[str] = []
    paginator = client.get_paginator("list_task_definitions")
    for page in paginator.paginate(familyPrefix=family, status="ACTIVE", sort="ASC"):
        arns.extend(page.get("taskDefinitionArns", []))
    return arns


def collect(
    profile: str | None = None,
    region: str | None = None,
    all_revisions: bool = False,
    families: Iterable[str] | None = None,
) -> dict[str, Any]:
    """Describe every ACTIVE task definition reachable with the given credentials.

    By default only the latest ACTIVE revision of each family is described,
    because that is the one a service will actually deploy. ``all_revisions``
    widens the sweep to every ACTIVE revision, which is slower and far noisier.
    """
    session = _session(profile, region)
    client = session.client("ecs")
    targets = list(families) if families else _families(client)

    definitions: list[dict[str, Any]] = []
    tags: dict[str, list[dict[str, str]]] = {}
    for family in sorted(targets):
        refs = _revision_arns(client, family) if all_revisions else [family]
        for ref in refs:
            response = client.describe_task_definition(
                taskDefinition=ref, include=["TAGS"]
            )
            definition = response["taskDefinition"]
            definitions.append(definition)
            if response.get("tags"):
                tags[definition["taskDefinitionArn"]] = response["tags"]

    return {
        "schema_version": SCHEMA_VERSION,
        "collected_at": _utcnow(),
        "region": client.meta.region_name,
        "all_revisions": all_revisions,
        "task_definitions": definitions,
        "tags": tags,
    }


def load(path: str) -> dict[str, Any]:
    """Replay a payload written by ``--dump-json``.

    Accepts either a full payload or a bare list of task definitions, so a
    hand-made fixture or the output of ``aws ecs describe-task-definition``
    piped into a file both work.
    """
    with open(path, encoding="utf-8") as handle:
        try:
            raw = json.load(handle)
        except json.JSONDecodeError as exc:
            raise CollectionError(f"{path}: not valid JSON ({exc})") from exc

    if isinstance(raw, list):
        return {
            "schema_version": SCHEMA_VERSION,
            "collected_at": None,
            "region": None,
            "all_revisions": False,
            "task_definitions": raw,
            "tags": {},
        }
    if not isinstance(raw, dict):
        raise CollectionError(f"{path}: expected an object or a list of task definitions")

    if "task_definitions" in raw:
        payload = dict(raw)
    elif "taskDefinition" in raw:
        payload = {"task_definitions": [raw["taskDefinition"]]}
    elif "family" in raw and "containerDefinitions" in raw:
        payload = {"task_definitions": [raw]}
    else:
        raise CollectionError(
            f"{path}: no task definitions found "
            "(expected 'task_definitions', 'taskDefinition', or a task definition object)"
        )

    payload.setdefault("schema_version", SCHEMA_VERSION)
    payload.setdefault("collected_at", None)
    payload.setdefault("region", None)
    payload.setdefault("all_revisions", False)
    payload.setdefault("tags", {})
    if not isinstance(payload["task_definitions"], list):
        raise CollectionError(f"{path}: 'task_definitions' must be a list")
    return payload


#: "1 vCPU", ".25 vcpu" and "2GB", "0.5 GB": the string forms RegisterTaskDefinition
#: accepts for task-level cpu and memory and converts to units at registration.
#: https://docs.aws.amazon.com/AmazonECS/latest/APIReference/API_RegisterTaskDefinition.html
_VCPU = re.compile(r"^\s*(\d+(?:\.\d+)?|\.\d+)\s*vcpu\s*$", re.IGNORECASE)
_GB = re.compile(r"^\s*(\d+(?:\.\d+)?|\.\d+)\s*gb\s*$", re.IGNORECASE)


def _to_units(value: Any, pattern: re.Pattern[str]) -> Any:
    """Convert a vCPU or GB string to the integer string ECS stores after registration.

    Anything that does not match, or does not land on a whole unit, is returned
    as is so the rules report it the same way they would for a registered one.
    """
    if not isinstance(value, str):
        return value
    match = pattern.match(value)
    if not match:
        return value
    units = float(match.group(1)) * 1024
    if not units.is_integer():
        return value
    return str(int(units))


def _taskdef_from(raw: Any, path: str) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Pull one task definition out of a register input or a describe output."""
    tags: list[dict[str, str]] = []
    if isinstance(raw, dict) and isinstance(raw.get("taskDefinition"), dict):
        tags = raw.get("tags") or []
        raw = raw["taskDefinition"]
    if not isinstance(raw, dict) or "containerDefinitions" not in raw:
        raise CollectionError(
            f"{path}: not a task definition "
            "(expected register-task-definition input or describe-task-definition output)"
        )
    if not raw.get("family"):
        raise CollectionError(f"{path}: task definition has no 'family'")
    if not isinstance(raw["containerDefinitions"], list):
        raise CollectionError(f"{path}: 'containerDefinitions' must be a list")

    definition = dict(raw)
    if "cpu" in definition:
        definition["cpu"] = _to_units(definition["cpu"], _VCPU)
    if "memory" in definition:
        definition["memory"] = _to_units(definition["memory"], _GB)
    return definition, tags


def _taskdef_files(paths: Iterable[str]) -> list[Path]:
    files: list[Path] = []
    for raw_path in paths:
        path = Path(raw_path)
        if path.is_dir():
            found = sorted(p for p in path.glob("*.json") if p.is_file())
            if not found:
                raise CollectionError(f"{raw_path}: no .json files in directory")
            files.extend(found)
        else:
            files.append(path)
    return files


def load_taskdefs(paths: Iterable[str]) -> dict[str, Any]:
    """Build a payload from task definition files that were never registered.

    Each file holds one task definition: either the input of
    ``aws ecs register-task-definition --cli-input-json`` or the output of
    ``aws ecs describe-task-definition``. A directory means every ``*.json``
    file directly inside it. Unregistered definitions have no revision and no
    ARN, so findings are named by ``family`` and the file they came from.
    """
    definitions: list[dict[str, Any]] = []
    sources: list[str] = []
    tags: dict[str, list[dict[str, str]]] = {}
    for path in _taskdef_files(paths):
        with open(path, encoding="utf-8") as handle:
            try:
                raw = json.load(handle)
            except json.JSONDecodeError as exc:
                raise CollectionError(f"{path}: not valid JSON ({exc})") from exc
        definition, definition_tags = _taskdef_from(raw, str(path))
        definitions.append(definition)
        sources.append(str(path))
        arn = definition.get("taskDefinitionArn")
        if arn and definition_tags:
            tags[arn] = definition_tags

    return {
        "schema_version": SCHEMA_VERSION,
        "collected_at": None,
        "region": None,
        "all_revisions": False,
        "task_definitions": definitions,
        "sources": sources,
        "tags": tags,
    }


def dump(payload: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")
