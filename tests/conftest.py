import copy
import json
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def messy_path() -> Path:
    return FIXTURES / "messy-dump.json"


@pytest.fixture
def messy(messy_path: Path) -> dict:
    return json.loads(messy_path.read_text(encoding="utf-8"))


def make_task(**overrides) -> dict:
    """A minimal, clean Fargate task definition to mutate in a single test."""
    task = {
        "family": "unit",
        "revision": 1,
        "taskDefinitionArn": "arn:aws:ecs:eu-central-1:111122223333:task-definition/unit:1",
        "networkMode": "awsvpc",
        "requiresCompatibilities": ["FARGATE"],
        "cpu": "256",
        "memory": "512",
        "executionRoleArn": "arn:aws:iam::111122223333:role/ecsTaskExecutionRole",
        "taskRoleArn": "arn:aws:iam::111122223333:role/unit-app",
        "containerDefinitions": [
            {
                "name": "app",
                "image": "registry.example.com/app@sha256:"
                + "a" * 64,
                "essential": True,
                "user": "10001",
                "readonlyRootFilesystem": True,
                "healthCheck": {"command": ["CMD-SHELL", "true"]},
                "environment": [{"name": "LOG_LEVEL", "value": "info"}],
                "logConfiguration": {"logDriver": "awslogs", "options": {}},
            }
        ],
    }
    container_overrides = overrides.pop("container", None)
    task = {**task, **copy.deepcopy(overrides)}
    if container_overrides:
        container = dict(task["containerDefinitions"][0])
        for key, value in container_overrides.items():
            if value is None:
                container.pop(key, None)
            else:
                container[key] = value
        task["containerDefinitions"] = [container]
    return task


@pytest.fixture
def payload_of():
    def _payload(*tasks) -> dict:
        return {
            "schema_version": 1,
            "collected_at": "2026-10-22T09:00:00+00:00",
            "region": "eu-central-1",
            "all_revisions": False,
            "tags": {},
            "task_definitions": list(tasks),
        }

    return _payload
