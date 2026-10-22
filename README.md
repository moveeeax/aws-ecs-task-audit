# aws-ecs-task-audit

[![ci](https://github.com/moveeeax/aws-ecs-task-audit/actions/workflows/ci.yml/badge.svg)](https://github.com/moveeeax/aws-ecs-task-audit/actions/workflows/ci.yml)
[![python](https://img.shields.io/badge/python-3.9%20%7C%203.11%20%7C%203.12-blue)](https://www.python.org/)
[![license](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A task definition is the one place where a container's whole security posture is declared,
and it is the one place nobody reviews. The console renders it as four collapsible panels
and never says *this password is in plaintext* or *this image tag will drift under you*.

`aws-ecs-task-audit` reads your ACTIVE task definitions and reports the structural mistakes
that are all visible in the JSON and all invisible in the UI.

## What it checks

| rule | severity | what it means |
| --- | --- | --- |
| `plaintext-secret` | high | a credential sits in `environment` instead of `secrets`, so anyone who can call `DescribeTaskDefinition` can read it |
| `invalid-fargate-size` | high | the `cpu`/`memory` pair is not a supported Fargate combination, so `RunTask` fails at launch, not at registration |
| `privileged` | high | `privileged: true` hands the container the host |
| `host-network` | high | `networkMode: host` with published ports, which pins the task to one instance and bypasses its security group |
| `mutable-image-tag` | medium | no digest and a moving tag, so a restart can ship a different build |
| `no-logging` | medium | no `logConfiguration`, so container output is unreachable once the task stops |
| `root-user` | medium | `user` is unset, `0`, or `root` |
| `missing-task-role` | medium | no `taskRoleArn`, or one identical to `executionRoleArn`, which collapses two trust boundaries into one |
| `unbounded-container` | medium | an EC2 container with no `memory` and no `memoryReservation`, so one leak evicts its neighbours |
| `no-healthcheck` | low | an essential container with no `healthCheck` |
| `writable-root-fs` | low | `readonlyRootFilesystem` is not set |

## How it works

Collection and analysis are separate on purpose. The collector calls
`list_task_definition_families` and `describe_task_definition` and returns a plain dict;
the rule engine is a pure function of that dict. So `--dump-json` writes a payload you can
commit, mail to a colleague, or replay with `--from-json` — and the whole test suite runs
offline against JSON fixtures with no AWS account.

By default only the latest ACTIVE revision of each family is described, because that is the
one a service will actually deploy. `--all-revisions` widens the sweep.

## Install

```bash
pip install "aws-ecs-task-audit[aws] @ git+https://github.com/moveeeax/aws-ecs-task-audit"
```

For offline replay only, the `aws` extra (boto3) is unnecessary.

## Usage

```bash
# audit everything the profile can see
aws-ecs-task-audit --profile prod --region eu-central-1

# snapshot now, analyse later
aws-ecs-task-audit --profile prod --dump-json /tmp/tasks.json

# replay offline, machine readable
aws-ecs-task-audit --from-json /tmp/tasks.json --format json \
  | jq '.findings[] | select(.rule=="plaintext-secret")'

# gate a pipeline on the two that actually break things
aws-ecs-task-audit --fail-on plaintext-secret,invalid-fargate-size \
  --ignore-family legacy-batch-worker
```

Against the bundled example:

```console
$ aws-ecs-task-audit --from-json examples/messy-dump.json --severity high
batch-worker:7
  HIGH host-network           worker
        networkMode host binds 9000 directly on the instance; a second task of this family cannot be
        placed there and the port bypasses the task's own security group
  HIGH plaintext-secret       worker
        environment variable UPSTREAM_DSN is named like a credential; anyone who can call
        DescribeTaskDefinition can read it. Move it to the secrets block and reference Secrets
        Manager or SSM.
  HIGH privileged             worker
        privileged: true gives the container the host's device access and effectively the host
        itself

checkout-api:94
  HIGH invalid-fargate-size   task
        cpu 256 with memory 8192 is not a supported Fargate combination; RunTask fails at launch
        time, not at registration. Nearest supported pair is cpu 1024 with memory 8192.
  HIGH plaintext-secret       web
        environment variable DB_PASSWORD is named like a credential; anyone who can call
        DescribeTaskDefinition can read it. Move it to the secrets block and reference Secrets
        Manager or SSM.

5 finding(s) across 3 task definition(s): 5 high, 0 medium, 0 low.
```

### Options

| flag | effect |
| --- | --- |
| `--profile`, `--region` | credentials and region for live collection |
| `--family NAME` | limit collection to one family (repeatable) |
| `--all-revisions` | describe every ACTIVE revision, not just the latest |
| `--dump-json FILE` | write the collected payload for offline replay |
| `--from-json FILE` | replay a payload instead of calling AWS |
| `--format text\|json` | output shape (default `text`) |
| `--severity low\|medium\|high` | suppress findings below this level |
| `--ignore-rule RULES` | comma separated rule names to skip (repeatable) |
| `--ignore-family FAMILIES` | comma separated families to skip (repeatable) |
| `--fail-on RULES` | rule names that make the run exit 1 |

Exit codes: `0` nothing matched `--fail-on`, `1` something did, `2` usage error —
an unknown rule name, an unreadable input, or a failed AWS call.

### IAM

Read-only. `ecs:ListTaskDefinitionFamilies`, `ecs:ListTaskDefinitions`,
`ecs:DescribeTaskDefinition`.

## Development

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check src tests
pytest
```

The fixtures in `tests/fixtures/` are real task definition shapes. Adding a rule means
adding a check function in `src/aws_ecs_task_audit/rules.py`, registering it in `RULES`,
and adding a positive and a negative case — the negative case matters more, because a
linter that cries wolf gets turned off.

## License

MIT. See [LICENSE](LICENSE).
