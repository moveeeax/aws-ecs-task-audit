"""Collection of ECS task definitions.

The collector is deliberately thin: it talks to the ECS API and returns a plain
dict. Every rule in :mod:`aws_ecs_task_audit.rules` consumes that dict and
nothing else, which is why the whole rule suite runs offline against JSON
fixtures and CI needs no AWS credentials.
"""

from __future__ import annotations

import datetime as _dt
import json
from collections.abc import Iterable
from typing import Any

from . import SCHEMA_VERSION


class CollectionError(RuntimeError):
    """Raised when a payload cannot be collected or replayed."""


def _utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0).isoformat()


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


def dump(payload: dict[str, Any], path: str) -> None:
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, default=str)
        handle.write("\n")
