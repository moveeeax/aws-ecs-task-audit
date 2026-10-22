import pytest
from conftest import make_task

from aws_ecs_task_audit.rules import (
    UnknownRuleError,
    _nearest_valid_pair,
    _parse_image,
    audit,
)


def rules_fired(payload, **kwargs):
    return sorted({f.rule for f in audit(payload, **kwargs)})


def find(payload, rule, **kwargs):
    return [f for f in audit(payload, **kwargs) if f.rule == rule]


# --------------------------------------------------------------------------- #
# plaintext-secret
# --------------------------------------------------------------------------- #


def test_password_in_environment_is_reported_by_name(payload_of):
    task = make_task(
        container={"environment": [{"name": "DB_PASSWORD", "value": "hunter2-but-longer"}]}
    )
    hits = find(payload_of(task), "plaintext-secret")
    assert len(hits) == 1
    assert "DB_PASSWORD" in hits[0].message
    assert hits[0].container == "app"
    assert hits[0].severity == "high"


def test_same_credential_moved_into_secrets_is_clean(payload_of):
    task = make_task(
        container={
            "environment": [{"name": "LOG_LEVEL", "value": "info"}],
            "secrets": [
                {
                    "name": "DB_PASSWORD",
                    "valueFrom": "arn:aws:secretsmanager:eu-central-1:1111:secret:db-AbCdEf",
                }
            ],
        }
    )
    assert find(payload_of(task), "plaintext-secret") == []


@pytest.mark.parametrize(
    "name",
    ["PUBLIC_KEY", "PARTITION_KEY", "SORT_KEY", "SECRET_ARN", "TOKEN_URL", "LOG_LEVEL"],
)
def test_identifier_shaped_names_are_not_credentials(payload_of, name):
    task = make_task(container={"environment": [{"name": name, "value": "whatever"}]})
    assert find(payload_of(task), "plaintext-secret") == []


@pytest.mark.parametrize(
    "value",
    [
        "AKIAIOSFODNN7EXAMPLE",
        "postgres://svc:s3cr3t-value@db.internal:5432/app",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIE...",
    ],
)
def test_credential_shaped_values_are_caught_under_a_neutral_name(payload_of, value):
    task = make_task(container={"environment": [{"name": "UPSTREAM", "value": value}]})
    assert len(find(payload_of(task), "plaintext-secret")) == 1


def test_plain_url_value_is_not_a_credential(payload_of):
    task = make_task(
        container={
            "environment": [
                {
                    "name": "QUEUE_URL",
                    "value": "https://sqs.eu-central-1.amazonaws.com/111122223333/jobs",
                }
            ]
        }
    )
    assert find(payload_of(task), "plaintext-secret") == []


# --------------------------------------------------------------------------- #
# mutable-image-tag
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("image", ["app:latest", "app:stable", "app:main", "app"])
def test_moving_tags_are_reported(payload_of, image):
    task = make_task(container={"image": image})
    assert len(find(payload_of(task), "mutable-image-tag")) == 1


@pytest.mark.parametrize(
    "image",
    [
        "app:1.4.2",
        "registry.example.com:5000/team/app:1.4.2",
        "app@sha256:" + "b" * 64,
        "app:latest@sha256:" + "b" * 64,
    ],
)
def test_pinned_images_are_clean(payload_of, image):
    task = make_task(container={"image": image})
    assert find(payload_of(task), "mutable-image-tag") == []


def test_registry_port_is_not_mistaken_for_a_tag():
    repo, tag, digest = _parse_image("registry.example.com:5000/team/app")
    assert (repo, tag, digest) == ("registry.example.com:5000/team/app", None, None)


# --------------------------------------------------------------------------- #
# invalid-fargate-size
# --------------------------------------------------------------------------- #


def test_impossible_fargate_pair_names_a_valid_one(payload_of):
    task = make_task(cpu="256", memory="8192")
    hits = find(payload_of(task), "invalid-fargate-size")
    assert len(hits) == 1
    assert "cpu 1024 with memory 8192" in hits[0].message
    assert hits[0].container is None


def test_supported_fargate_pair_is_clean(payload_of):
    assert find(payload_of(make_task(cpu="256", memory="512")), "invalid-fargate-size") == []


def test_ec2_task_is_not_checked_against_fargate_sizes(payload_of):
    task = make_task(requiresCompatibilities=["EC2"], cpu="256", memory="8192")
    assert find(payload_of(task), "invalid-fargate-size") == []


@pytest.mark.parametrize(
    "cpu,memory,expected",
    [
        (256, 8192, (1024, 8192)),
        (512, 512, (512, 1024)),
        (1024, 3000, (1024, 3072)),
    ],
)
def test_nearest_valid_pair(cpu, memory, expected):
    """Never shrink what was asked for: an OOM kill is worse than an unregistrable task."""
    assert _nearest_valid_pair(cpu, memory) == expected


# --------------------------------------------------------------------------- #
# missing-task-role
# --------------------------------------------------------------------------- #


def test_task_role_equal_to_execution_role_is_distinguished(payload_of):
    role = "arn:aws:iam::111122223333:role/ecsTaskExecutionRole"
    task = make_task(taskRoleArn=role, executionRoleArn=role)
    hits = find(payload_of(task), "missing-task-role")
    assert len(hits) == 1
    assert "same role as executionRoleArn" in hits[0].message


def test_absent_task_role_has_its_own_reason(payload_of):
    task = make_task()
    task.pop("taskRoleArn")
    hits = find(payload_of(task), "missing-task-role")
    assert len(hits) == 1
    assert "absent" in hits[0].message
    assert "same role" not in hits[0].message


def test_distinct_roles_are_clean(payload_of):
    assert find(payload_of(make_task()), "missing-task-role") == []


# --------------------------------------------------------------------------- #
# the remaining rules
# --------------------------------------------------------------------------- #


def test_missing_log_configuration(payload_of):
    task = make_task(container={"logConfiguration": None})
    assert len(find(payload_of(task), "no-logging")) == 1


def test_healthcheck_only_required_on_essential_containers(payload_of):
    essential = make_task(container={"healthCheck": None})
    assert len(find(payload_of(essential), "no-healthcheck")) == 1
    sidecar = make_task(container={"healthCheck": None, "essential": False})
    assert find(payload_of(sidecar), "no-healthcheck") == []


@pytest.mark.parametrize("user", [None, "0", "root", "0:0"])
def test_root_user_detection(payload_of, user):
    task = make_task(container={"user": user})
    assert len(find(payload_of(task), "root-user")) == 1


@pytest.mark.parametrize("user", ["10001", "app", "1000:1000"])
def test_non_root_user_is_clean(payload_of, user):
    assert find(payload_of(make_task(container={"user": user})), "root-user") == []


def test_writable_root_filesystem(payload_of):
    task = make_task(container={"readonlyRootFilesystem": None})
    assert len(find(payload_of(task), "writable-root-fs")) == 1


def test_privileged_container(payload_of):
    task = make_task(container={"privileged": True})
    assert len(find(payload_of(task), "privileged")) == 1


def test_host_network_with_published_ports(payload_of):
    task = make_task(
        networkMode="host",
        requiresCompatibilities=["EC2"],
        container={"portMappings": [{"containerPort": 9000, "hostPort": 9000}]},
    )
    hits = find(payload_of(task), "host-network")
    assert len(hits) == 1
    assert "9000" in hits[0].message


def test_host_network_without_ports_is_clean(payload_of):
    task = make_task(networkMode="host", requiresCompatibilities=["EC2"])
    assert find(payload_of(task), "host-network") == []


def test_unbounded_ec2_container(payload_of):
    task = make_task(requiresCompatibilities=["EC2"])
    task.pop("memory")
    assert len(find(payload_of(task), "unbounded-container")) == 1

    bounded = make_task(requiresCompatibilities=["EC2"], container={"memoryReservation": 512})
    bounded.pop("memory")
    assert find(payload_of(bounded), "unbounded-container") == []


def test_fargate_container_is_never_unbounded(payload_of):
    assert find(payload_of(make_task()), "unbounded-container") == []


# --------------------------------------------------------------------------- #
# engine behaviour
# --------------------------------------------------------------------------- #


def test_clean_task_produces_nothing(payload_of):
    assert audit(payload_of(make_task())) == []


def test_fixture_dump_fires_the_expected_rules(messy):
    assert rules_fired(messy) == [
        "host-network",
        "invalid-fargate-size",
        "missing-task-role",
        "mutable-image-tag",
        "no-healthcheck",
        "no-logging",
        "plaintext-secret",
        "privileged",
        "root-user",
        "unbounded-container",
        "writable-root-fs",
    ]
    assert {f.family for f in audit(messy)} == {"checkout-api", "batch-worker"}


def test_ignore_rule_suppresses_only_its_target(messy):
    baseline = audit(messy)
    filtered = audit(messy, ignore_rules=["no-healthcheck"])
    assert {f.rule for f in filtered} == {f.rule for f in baseline} - {"no-healthcheck"}
    assert len(filtered) == len([f for f in baseline if f.rule != "no-healthcheck"])


def test_ignore_family_suppresses_only_its_target(messy):
    filtered = audit(messy, ignore_families=["batch-worker"])
    assert {f.family for f in filtered} == {"checkout-api"}


def test_severity_floor(messy):
    assert {f.severity for f in audit(messy, min_severity="high")} == {"high"}
    assert {f.severity for f in audit(messy, min_severity="medium")} == {"high", "medium"}


def test_unknown_rule_name_raises(messy):
    with pytest.raises(UnknownRuleError) as excinfo:
        audit(messy, ignore_rules=["no-such-rule"])
    assert "no-such-rule" in str(excinfo.value)


def test_unknown_severity_raises(messy):
    with pytest.raises(ValueError):
        audit(messy, min_severity="catastrophic")


def test_findings_are_ordered_by_family_then_severity(messy):
    findings = audit(messy)
    assert [f.family for f in findings] == sorted(f.family for f in findings)
    checkout = [f for f in findings if f.family == "checkout-api"]
    severities = [f.severity for f in checkout]
    assert severities == sorted(severities, key=lambda s: ["high", "medium", "low"].index(s))
