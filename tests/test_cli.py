import json

import pytest

from aws_ecs_task_audit import cli, collector


def run(capsys, *argv):
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def test_text_report_lists_family_and_revision(capsys, messy_path):
    code, out, _ = run(capsys, "--from-json", str(messy_path))
    assert code == 0
    assert "checkout-api:94" in out
    assert "plaintext-secret" in out
    assert "well-behaved" not in out
    assert "finding(s) across 3 task definition(s)" in out


def test_json_report_is_machine_readable(capsys, messy_path):
    code, out, _ = run(capsys, "--from-json", str(messy_path), "--format", "json")
    assert code == 0
    document = json.loads(out)
    assert document["task_definitions_scanned"] == 3
    assert document["counts"]["high"] > 0
    rules = {f["rule"] for f in document["findings"]}
    assert "plaintext-secret" in rules
    secret = next(
        f
        for f in document["findings"]
        if f["rule"] == "plaintext-secret" and f["family"] == "checkout-api"
    )
    assert secret["revision"] == 94
    assert secret["container"] == "web"
    assert "DB_PASSWORD" in secret["message"]


def test_fail_on_matching_rule_exits_1(capsys, messy_path):
    code, _, _ = run(capsys, "--from-json", str(messy_path), "--fail-on", "plaintext-secret")
    assert code == 1


def test_fail_on_rule_that_did_not_fire_exits_0(capsys, messy_path):
    code, _, _ = run(
        capsys,
        "--from-json",
        str(messy_path),
        "--ignore-family",
        "checkout-api,batch-worker",
        "--fail-on",
        "plaintext-secret",
    )
    assert code == 0


def test_unknown_rule_in_fail_on_exits_2(capsys, messy_path):
    code, _, err = run(capsys, "--from-json", str(messy_path), "--fail-on", "not-a-rule")
    assert code == 2
    assert "unknown rule name" in err


def test_unknown_rule_in_ignore_rule_exits_2(capsys, messy_path):
    code, _, err = run(capsys, "--from-json", str(messy_path), "--ignore-rule", "nope")
    assert code == 2
    assert "nope" in err


def test_unknown_severity_is_rejected_by_argparse(messy_path):
    with pytest.raises(SystemExit) as excinfo:
        cli.main(["--from-json", str(messy_path), "--severity", "catastrophic"])
    assert excinfo.value.code == 2


def test_comma_and_repeated_flags_are_both_accepted(capsys, messy_path):
    _, split_out, _ = run(
        capsys,
        "--from-json",
        str(messy_path),
        "--ignore-rule",
        "no-healthcheck",
        "--ignore-rule",
        "writable-root-fs",
    )
    _, joined_out, _ = run(
        capsys,
        "--from-json",
        str(messy_path),
        "--ignore-rule",
        "no-healthcheck,writable-root-fs",
    )
    assert split_out == joined_out


def test_from_json_is_reproducible_and_never_calls_aws(capsys, messy_path, monkeypatch):
    def explode(*args, **kwargs):
        raise AssertionError("--from-json must not touch the network")

    monkeypatch.setattr(cli, "collect", explode)
    _, first, _ = run(capsys, "--from-json", str(messy_path), "--format", "json")
    _, second, _ = run(capsys, "--from-json", str(messy_path), "--format", "json")
    assert first == second
    assert json.loads(first)["findings"]


def test_dump_json_round_trips(capsys, messy_path, tmp_path):
    out_file = tmp_path / "dump.json"
    run(capsys, "--from-json", str(messy_path), "--dump-json", str(out_file))
    assert out_file.exists()
    _, from_original, _ = run(capsys, "--from-json", str(messy_path), "--format", "json")
    _, from_dump, _ = run(capsys, "--from-json", str(out_file), "--format", "json")
    assert json.loads(from_original)["findings"] == json.loads(from_dump)["findings"]


def test_bare_list_of_task_definitions_is_accepted(tmp_path, messy, capsys):
    path = tmp_path / "list.json"
    path.write_text(json.dumps(messy["task_definitions"]), encoding="utf-8")
    code, out, _ = run(capsys, "--from-json", str(path))
    assert code == 0
    assert "checkout-api:94" in out


def test_single_describe_task_definition_response_is_accepted(tmp_path, messy, capsys):
    path = tmp_path / "one.json"
    path.write_text(
        json.dumps({"taskDefinition": messy["task_definitions"][0]}), encoding="utf-8"
    )
    code, out, _ = run(capsys, "--from-json", str(path))
    assert code == 0
    assert "checkout-api:94" in out


def test_missing_file_exits_2(capsys, tmp_path):
    code, _, err = run(capsys, "--from-json", str(tmp_path / "nope.json"))
    assert code == 2
    assert "nope.json" in err


def test_invalid_json_exits_2(capsys, tmp_path):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(path))
    assert code == 2
    assert "not valid JSON" in err


def test_unrecognised_object_exits_2(capsys, tmp_path):
    path = tmp_path / "other.json"
    path.write_text(json.dumps({"hello": "world"}), encoding="utf-8")
    code, _, err = run(capsys, "--from-json", str(path))
    assert code == 2
    assert "no task definitions found" in err


def test_clean_payload_says_so(capsys, tmp_path, messy):
    path = tmp_path / "clean.json"
    clean = dict(messy)
    clean["task_definitions"] = [
        t for t in messy["task_definitions"] if t["family"] == "well-behaved"
    ]
    path.write_text(json.dumps(clean), encoding="utf-8")
    code, out, _ = run(capsys, "--from-json", str(path))
    assert code == 0
    assert "No findings across 1 task definition(s)." in out


def test_load_rejects_a_scalar(tmp_path):
    path = tmp_path / "scalar.json"
    path.write_text("42", encoding="utf-8")
    with pytest.raises(collector.CollectionError):
        collector.load(str(path))
