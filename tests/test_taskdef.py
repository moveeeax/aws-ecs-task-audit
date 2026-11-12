import json
from pathlib import Path

import pytest
from conftest import make_task

from aws_ecs_task_audit import cli, collector
from aws_ecs_task_audit.rules import audit

EXAMPLES = Path(__file__).parent.parent / "examples"


def run(capsys, *argv):
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def register_input(**overrides) -> dict:
    """A clean task definition as it sits in a repo: no revision, no ARN."""
    task = make_task(**overrides)
    task.pop("revision")
    task.pop("taskDefinitionArn")
    return task


def write(path, document):
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_register_input_file_is_audited_and_named_by_family(capsys, tmp_path):
    path = write(
        tmp_path / "api.json",
        register_input(
            family="checkout-api",
            container={"environment": [{"name": "DB_PASSWORD", "value": "hunter2-but-longer"}]},
        ),
    )
    code, out, _ = run(capsys, "--from-taskdef", str(path), "--fail-on", "plaintext-secret")
    assert code == 1
    assert f"checkout-api  ({path})" in out
    assert "checkout-api:0" not in out
    assert "plaintext-secret" in out


def test_clean_register_input_has_no_findings(capsys, tmp_path):
    path = write(tmp_path / "unit.json", register_input())
    code, out, _ = run(capsys, "--from-taskdef", str(path))
    assert code == 0
    assert "No findings across 1 task definition(s)." in out


def test_describe_output_keeps_revision_and_records_source(capsys, tmp_path):
    task = make_task(container={"user": None})
    path = write(tmp_path / "described.json", {"taskDefinition": task, "tags": []})
    code, out, _ = run(capsys, "--from-taskdef", str(path), "--format", "json")
    assert code == 0
    finding = json.loads(out)["findings"][0]
    assert finding["rule"] == "root-user"
    assert finding["revision"] == 1
    assert finding["source"] == str(path)


def test_directory_reads_every_json_file_in_name_order(capsys, tmp_path):
    write(tmp_path / "b.json", register_input(family="beta", container={"user": None}))
    write(tmp_path / "a.json", register_input(family="alpha", container={"user": None}))
    (tmp_path / "notes.txt").write_text("not a task definition", encoding="utf-8")
    payload = collector.load_taskdefs([str(tmp_path)])
    assert [t["family"] for t in payload["task_definitions"]] == ["alpha", "beta"]
    assert payload["sources"] == [str(tmp_path / "a.json"), str(tmp_path / "b.json")]

    code, out, _ = run(capsys, "--from-taskdef", str(tmp_path))
    assert code == 0
    assert "across 2 task definition(s)" in out


def test_flag_is_repeatable(tmp_path):
    first = write(tmp_path / "one.json", register_input(family="one"))
    second = write(tmp_path / "two.json", register_input(family="two"))
    payload = collector.load_taskdefs([str(first), str(second)])
    assert [t["family"] for t in payload["task_definitions"]] == ["one", "two"]


def test_same_family_in_two_files_is_reported_separately(capsys, tmp_path):
    staging = write(tmp_path / "staging.json", register_input(container={"user": None}))
    prod = write(tmp_path / "prod.json", register_input(container={"user": None}))
    _, out, _ = run(capsys, "--from-taskdef", str(staging), "--from-taskdef", str(prod))
    assert f"unit  ({staging})" in out
    assert f"unit  ({prod})" in out


@pytest.mark.parametrize(
    ("cpu", "memory", "fires"),
    [
        ("1 vCPU", "2 GB", False),
        (".25 vcpu", "0.5GB", False),
        ("0.25 vCPU", "8 GB", True),
        ("1024", "2048", False),
    ],
)
def test_vcpu_and_gb_strings_are_converted_like_registration(tmp_path, cpu, memory, fires):
    path = write(tmp_path / "size.json", register_input(cpu=cpu, memory=memory))
    payload = collector.load_taskdefs([str(path)])
    fired = [f for f in audit(payload) if f.rule == "invalid-fargate-size"]
    assert bool(fired) is fires


def test_vcpu_string_becomes_units(tmp_path):
    path = write(tmp_path / "size.json", register_input(cpu="2 vCPU", memory="4GB"))
    task = collector.load_taskdefs([str(path)])["task_definitions"][0]
    assert task["cpu"] == "2048"
    assert task["memory"] == "4096"


def test_unconvertible_size_is_left_for_the_rule_to_report(tmp_path):
    path = write(tmp_path / "size.json", register_input(cpu="lots"))
    task = collector.load_taskdefs([str(path)])["task_definitions"][0]
    assert task["cpu"] == "lots"


def test_ignore_family_applies(capsys, tmp_path):
    path = write(tmp_path / "unit.json", register_input(container={"user": None}))
    _, out, _ = run(capsys, "--from-taskdef", str(path), "--ignore-family", "unit")
    assert "No findings" in out


def test_dump_json_round_trips_sources(capsys, tmp_path):
    path = write(tmp_path / "unit.json", register_input(container={"user": None}))
    dumped = tmp_path / "dump.json"
    _, direct, _ = run(
        capsys, "--from-taskdef", str(path), "--dump-json", str(dumped), "--format", "json"
    )
    _, replayed, _ = run(capsys, "--from-json", str(dumped), "--format", "json")
    assert json.loads(direct)["findings"] == json.loads(replayed)["findings"]


def test_from_taskdef_never_calls_aws(capsys, tmp_path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("--from-taskdef must not touch the network")

    monkeypatch.setattr(cli, "collect", explode)
    path = write(tmp_path / "unit.json", register_input())
    code, _, _ = run(capsys, "--from-taskdef", str(path))
    assert code == 0


def test_from_json_and_from_taskdef_are_exclusive(tmp_path, messy_path):
    path = write(tmp_path / "unit.json", register_input())
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--from-json", str(messy_path), "--from-taskdef", str(path)])
    assert excinfo.value.code == 2


@pytest.mark.parametrize(
    ("document", "message"),
    [
        ({"hello": "world"}, "not a task definition"),
        ([{"family": "a", "containerDefinitions": []}], "not a task definition"),
        ({"containerDefinitions": []}, "has no 'family'"),
        ({"family": "a", "containerDefinitions": {}}, "must be a list"),
    ],
)
def test_malformed_files_exit_2(capsys, tmp_path, document, message):
    path = write(tmp_path / "bad.json", document)
    code, _, err = run(capsys, "--from-taskdef", str(path))
    assert code == 2
    assert message in err


def test_invalid_json_exits_2(capsys, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, _, err = run(capsys, "--from-taskdef", str(path))
    assert code == 2
    assert "not valid JSON" in err


def test_missing_file_exits_2(capsys, tmp_path):
    code, _, err = run(capsys, "--from-taskdef", str(tmp_path / "nope.json"))
    assert code == 2
    assert "nope.json" in err


def test_empty_directory_exits_2(capsys, tmp_path):
    code, _, err = run(capsys, "--from-taskdef", str(tmp_path))
    assert code == 2
    assert "no .json files" in err


def test_bundled_taskdef_example(capsys):
    code, out, _ = run(
        capsys, "--from-taskdef", str(EXAMPLES / "taskdefs"), "--fail-on", "plaintext-secret"
    )
    assert code == 1
    assert "invalid-fargate-size" in out
    assert "cpu 256 with memory 8192" in out
