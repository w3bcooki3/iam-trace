"""The sample account the web app loads (examples/sample, from scripts/build_sample.py).

Its point is that every screen has something to show, so these tests check that each feature
finds what the sample was built to contain. If a change to the engine makes one of these empty,
the sample needs updating, or the change broke something.
"""

from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from iamtrace import web_api

ROOT = Path(__file__).resolve().parents[2]
SAMPLE = ROOT / "examples" / "sample"


def _builder():  # type: ignore[no-untyped-def]
    spec = importlib.util.spec_from_file_location("build_sample", ROOT / "scripts" / "build_sample.py")
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def text(name: str) -> str:
    return (SAMPLE / name).read_text(encoding="utf-8")


def test_files_are_up_to_date() -> None:
    for name, content in _builder().files().items():
        assert (SAMPLE / name).read_text(encoding="utf-8") == content, f"run python3 scripts/build_sample.py ({name})"


def analysis() -> dict:  # type: ignore[type-arg]
    q = json.loads(text("queries.json"))
    out = json.loads(
        web_api.analyze_account(
            text("auth-details.json"),
            q["start"],
            text("scps.json"),
            False,
            text("inventory.json"),
            text("credential-report.csv"),
            text("last-accessed.json"),
        )
    )
    assert "error" not in out, out
    return out


def test_every_screen_has_something() -> None:
    out = analysis()
    paths = out["account"]["paths"]
    # Paths of one and two steps, one gated on MFA, and some from the starting principal.
    assert {len(p["steps"]) for p in paths} >= {1, 2}
    assert any(p["open"] is False for p in paths)
    assert out["result"]["paths"]
    # The SCP blocks the analytics role's glue-002, though its policy allows glue:*.
    analytics = next(p for p in out["account"]["principals"] if p["arn"].endswith("role/analytics"))
    assert not any(t["id"] == "glue-002" for t in analytics["techniques"])
    # Entry points: GitHub, a partner account, SAML and users with keys.
    entries = {e["principal"].rsplit(":", 1)[-1] for e in out["entry_points"]["entries"]}
    assert {"role/github-deploy", "role/partner-audit", "role/sso-readonly", "user/bob", "user/dev-legacy"} <= entries
    # Data access: every kind, one of them critical.
    kinds = {r["kind"] for r in out["data"]["resources"]}
    assert kinds == {"s3-bucket", "kms-key", "secretsmanager-secret", "dynamodb-table", "sns-topic", "sqs-queue"}
    assert any(r["rating"] == "Critical" for r in out["data"]["resources"])
    # Unused access has edits, and they close paths.
    assert out["unused"]["edits"]
    assert out["unused"]["impact"]["closed"]


def test_terraform_plan_opens_a_path() -> None:
    r = json.loads(web_api.terraform_query(text("terraform-plan.json"), text("auth-details.json")))
    assert r["account"]["new_paths"]
    assert r["account"]["new_entry_points"]


def test_who_can_query_has_an_answer() -> None:
    q = json.loads(text("queries.json"))
    r = json.loads(
        web_api.who_can_query(
            text("auth-details.json"),
            q["whocan"]["action"],
            q["whocan"]["resource"],
            "",
            text("scps.json"),
            text("inventory.json"),
        )
    )
    assert "error" not in r, r
    assert r["result"]["direct"] or r["result"]["via"]
