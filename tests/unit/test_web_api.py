"""The functions the web page calls inside Pyodide."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from iamtrace import web_api

POLICY = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
)


def test_can_allow() -> None:
    out = json.loads(
        web_api.can(
            json.dumps(
                {
                    "principal": "arn:aws:iam::111122223333:user/alice",
                    "action": "s3:GetObject",
                    "resource": "arn:aws:s3:::b/k",
                    "resource_account": "111122223333",
                    "identity": [POLICY],
                    "context": "aws:SourceIp=10.0.0.1\n",
                }
            )
        )
    )
    assert out["decision"] == "Allow"
    assert "Trace:" in out["text"]


def test_can_reports_errors_instead_of_raising() -> None:
    out = json.loads(
        web_api.can(
            json.dumps(
                {
                    "principal": "arn:aws:iam::111122223333:user/alice",
                    "action": "s3:GetObject",
                    "identity": ['{"Statement": [{"Effect": "Nope", "Action": "*", "Resource": "*"}]}'],
                }
            )
        )
    )
    assert "Effect must be Allow or Deny" in out["error"]


def test_can_with_scp_levels() -> None:
    scp = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "ec2:*", "Resource": "*"}]})
    out = json.loads(
        web_api.can(
            json.dumps(
                {
                    "principal": "arn:aws:iam::111122223333:user/alice",
                    "action": "s3:GetObject",
                    "resource": "*",
                    "identity": [POLICY],
                    "scp": [scp],
                }
            )
        )
    )
    assert out["decision"] == "ImplicitDeny"


def test_diff_without_catalog(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    web_api._catalog.cache_clear()
    monkeypatch.setattr(web_api, "CATALOG_DIR", str(tmp_path / "none"))
    monkeypatch.setattr("iamtrace.catalog.PACKAGED", tmp_path / "none")
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    out = json.loads(web_api.diff(POLICY, POLICY))
    assert "catalog" in out["error"]
    web_api._catalog.cache_clear()


def test_diff_with_catalog(monkeypatch: pytest.MonkeyPatch, catalog_dir: Path) -> None:
    web_api._catalog.cache_clear()
    monkeypatch.setattr(web_api, "CATALOG_DIR", str(catalog_dir))
    new = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]})
    out = json.loads(web_api.diff(POLICY, new))
    assert "s3:PutObject" in out["text"]
    web_api._catalog.cache_clear()


def test_escalate() -> None:
    p = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:PutRolePolicy", "Resource": "*"}]}
    )
    out = json.loads(web_api.escalate(p))
    assert "iam-005" in out["text"]


def test_escalate_graph_for_single_policy() -> None:
    p = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
                    "Resource": "*",
                }
            ],
        }
    )
    graph = json.loads(web_api.escalate(p))["graph"]
    start = [n for n in graph["nodes"] if n["start"]]
    assert len(start) == 1
    assert any(e["label"].startswith("lambda-001") and e["confidence"] == "possible" for e in graph["edges"])


def test_escalate_graph_admin_node() -> None:
    p = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    graph = json.loads(web_api.escalate(p))["graph"]
    assert any(n["id"] == "admin" for n in graph["nodes"])
    assert len(graph["nodes"]) == 2


def test_escalate_account_example() -> None:
    text = (Path(__file__).resolve().parents[2] / "examples" / "account" / "auth-details.json").read_text()
    principals = json.loads(web_api.account_principals(text))["principals"]
    assert "arn:aws:iam::111122223333:user/dev" in principals
    out = json.loads(web_api.escalate_account(text, "arn:aws:iam::111122223333:user/dev"))
    labels = {(e["from"].rsplit("/", 1)[-1], e["to"].rsplit("/", 1)[-1], e["label"]) for e in out["graph"]["edges"]}
    assert ("dev", "ops", "sts-001") in labels
    assert ("ops", "ec2-admin", "ec2-001") in labels
    assert ("ec2-admin", "admin", "admin") in labels


ACCOUNT = (Path(__file__).parents[2] / "examples" / "account" / "auth-details.json").read_text()
DEV = "arn:aws:iam::111122223333:user/dev"


def test_analyze_account_summarises_every_principal() -> None:
    out = json.loads(web_api.analyze_account(ACCOUNT, DEV))
    assert "error" not in out
    by_arn = {p["arn"]: p for p in out["account"]["principals"]}
    assert by_arn[DEV]["path"] is not None
    assert [s["technique"] for s in by_arn[DEV]["path"]["steps"]] == ["sts-001", "ec2-001"]
    assert by_arn["arn:aws:iam::111122223333:role/ec2-admin"]["admin_equivalent"]
    assert out["inventory"]["users"] == 1 and out["inventory"]["roles"] == 5
    assert out["result"]["start"] == DEV
    assert json.loads(out["sarif"])["version"] == "2.1.0"


def test_analyze_account_scp_can_break_a_path() -> None:
    deny = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "ec2:RunInstances", "Resource": "*"}]}
    )
    allow = json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
    without = json.loads(web_api.analyze_account(ACCOUNT, DEV))
    with_scp = json.loads(web_api.analyze_account(ACCOUNT, DEV, f"[{allow}, {deny}]"))
    assert any(p["open"] for p in without["result"]["paths"])
    # The SCP breaks the open path; the break-glass path that needs MFA is not affected by it.
    assert not any(p["open"] for p in with_scp["result"]["paths"])
    assert with_scp["scps"] == 2


@pytest.mark.parametrize(
    ("text", "principal"),
    [("[]", DEV), ("{", DEV), (ACCOUNT, ""), (ACCOUNT, "arn:aws:iam::111122223333:user/nobody")],
)
def test_analyze_account_reports_errors(text: str, principal: str) -> None:
    assert "error" in json.loads(web_api.analyze_account(text, principal))


@pytest.fixture
def real_catalog(monkeypatch: pytest.MonkeyPatch) -> object:
    from iamtrace.catalog import PACKAGED

    web_api._catalog.cache_clear()
    monkeypatch.setattr(web_api, "CATALOG_DIR", str(PACKAGED))
    yield
    web_api._catalog.cache_clear()


@pytest.mark.usefixtures("real_catalog")
def test_check_policies_and_export_together() -> None:
    export = (Path(__file__).parents[2] / "examples" / "account" / "auth-details.json").read_text()
    admin = '{"Version":"2012-10-17","Statement":{"Effect":"Allow","Action":"*","Resource":"*"}}'
    out = json.loads(
        web_api.check(json.dumps([{"name": "admin.json", "text": admin}, {"name": "account.json", "text": export}]))
    )
    rules = {f["rule"] for f in out["result"]["findings"]}
    assert {"full-admin", "passrole-any-role"} <= rules
    assert out["result"]["summary"]["policies"] == 12  # 1 file + 6 inline + 5 trust policies
    assert out["result"]["findings"][0]["severity"] == "high"
    assert "Fix:" in out["text"] and json.loads(out["sarif"])["version"] == "2.1.0"


@pytest.mark.usefixtures("real_catalog")
def test_check_errors() -> None:
    assert "error" in json.loads(web_api.check("[]"))
    bad = json.loads(web_api.check(json.dumps([{"name": "x", "text": "{oops"}])))
    assert bad["result"]["findings"][0]["rule"] == "invalid-policy"


def test_analyze_account_with_inventory() -> None:
    inv = (Path(__file__).parents[2] / "examples" / "account" / "inventory.json").read_text()
    dev = "arn:aws:iam::111122223333:user/dev"
    without = json.loads(web_api.analyze_account(ACCOUNT, dev))
    with_inv = json.loads(web_api.analyze_account(ACCOUNT, dev, "", False, inv))

    def lambda_003(out: dict) -> dict:
        p = next(p for p in out["result"]["principals"] if p["arn"] == dev)
        return next(t for t in p["techniques"] if t["id"] == "lambda-003")

    assert lambda_003(without)["confidence"] == "possible" and without["resources"] is None
    assert lambda_003(with_inv)["confidence"] == "confirmed"
    assert lambda_003(with_inv)["via"] == ["arn:aws:lambda:us-east-1:111122223333:function:nightly-report"]
    assert with_inv["resources"] == {"ec2-instance": 1, "kms-key": 1, "lambda-function": 2, "s3-bucket": 2}
    bad = json.loads(web_api.analyze_account(ACCOUNT, dev, "", False, "{oops"))
    assert "inventory" in bad["error"]


def test_fix_plan_query_reuses_the_last_analysis() -> None:
    text = (Path(__file__).resolve().parents[2] / "examples/account/auth-details.json").read_text()
    dev = "arn:aws:iam::111122223333:user/dev"
    json.loads(web_api.analyze_account(text, dev))
    cached = web_api._LAST["everyone"]
    plan = json.loads(web_api.fix_plan_query(text, dev))
    assert web_api._LAST["everyone"] is cached
    assert plan["verified"] is True
    assert plan["changes"][0]["actions"] == ["iam:PassRole"]
    assert "_fixed_env" not in plan
    every = json.loads(web_api.fix_plan_query(text, ""))
    assert every["start"] is None and every["verified"]


def test_fix_plan_query_without_a_previous_analysis() -> None:
    text = (Path(__file__).resolve().parents[2] / "examples/account/auth-details.json").read_text()
    web_api._LAST.clear()
    plan = json.loads(web_api.fix_plan_query(text, "arn:aws:iam::111122223333:user/dev"))
    assert plan["status"] == "fixed"


def test_fix_plan_query_reports_errors() -> None:
    out = json.loads(web_api.fix_plan_query("{}", "arn:aws:iam::1:user/x"))
    assert "error" in out


def test_analyze_account_with_a_credential_report() -> None:
    text = (Path(__file__).resolve().parents[2] / "examples/account/auth-details.json").read_text()
    creds = (Path(__file__).resolve().parents[2] / "examples/account/credential-report.csv").read_text()
    out = json.loads(web_api.analyze_account(text, "arn:aws:iam::111122223333:user/dev", "", False, "", creds))
    ep = out["entry_points"]
    assert ep["credential_report"]["users"] == 1
    dev = next(e for e in ep["entries"] if e["principal"].endswith("user/dev"))
    assert "access key" in dev["exposure"]["who"]
    bad = json.loads(web_api.analyze_account(text, "arn:aws:iam::111122223333:user/dev", "", False, "", "x,y\n1,2"))
    assert "credential report" in bad["error"]


def test_data_exposure_and_query() -> None:
    root = Path(__file__).resolve().parents[2] / "examples/account"
    text = (root / "auth-details.json").read_text()
    inv = (root / "inventory.json").read_text()
    out = json.loads(web_api.analyze_account(text, "arn:aws:iam::111122223333:user/dev", "", False, inv))
    rows = out["data"]["resources"]
    assert rows[0]["resource"] == "arn:aws:s3:::example-public-assets" and rows[0]["rating"] == "Critical"
    r = json.loads(web_api.data_query(text, "arn:aws:s3:::example-reports", "read", "", inv))
    assert r["requires"] == ["s3:GetObject", "kms:Decrypt"]
    assert [b["principal"] for b in r["blocked_by_key"]] == ["arn:aws:iam::111122223333:role/report-runner"]
    bad = json.loads(web_api.data_query(text, "arn:aws:sqs:us-east-1:1:q", "read", "", inv))
    assert "S3 buckets" in bad["error"]


def test_terraform_query() -> None:
    root = Path(__file__).resolve().parents[2] / "examples"
    plan = (root / "terraform/plan.json").read_text()
    export = (root / "account/auth-details.json").read_text()
    out = json.loads(web_api.terraform_query(plan, export))
    assert out["summary"]["new_paths"] == 1
    assert out["markdown"].startswith("<!-- iam-trace-terraform -->")
    alone = json.loads(web_api.terraform_query(plan, ""))
    assert alone["account"] is None and alone["summary"]["documents"] == 3
    assert "error" in json.loads(web_api.terraform_query("{}", ""))
