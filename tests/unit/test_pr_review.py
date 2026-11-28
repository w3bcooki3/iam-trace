"""The pull-request review the GitHub Action runs, against a real temporary git repository."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

from iamtrace import pr_review


def git(cwd: Path, *args: str) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout.strip()


def write(repo: Path, path: str, doc: object) -> None:
    p = repo / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(doc, indent=2) if not isinstance(doc, str) else doc)


def policy(*actions: str) -> dict:
    return {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": list(actions), "Resource": "*"}]}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    r = tmp_path / "repo"
    r.mkdir()
    git(r, "init", "-q", "-b", "main")
    git(r, "config", "user.email", "t@example.com")
    git(r, "config", "user.name", "t")
    write(r, "policies/app.json", policy("s3:GetObject"))
    write(r, "policies/old.json", policy("s3:GetObject"))
    write(r, "config/settings.json", {"not": "a policy"})
    git(r, "add", "-A")
    git(r, "commit", "-q", "-m", "base")
    return r


def commit_change(repo: Path) -> tuple[str, str]:
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "policies/app.json", policy("s3:GetObject", "iam:PutRolePolicy"))
    write(repo, "policies/new.json", policy("lambda:InvokeFunction"))
    (repo / "policies/old.json").unlink()
    write(repo, "config/settings.json", {"not": "a policy", "changed": True})
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "change")
    return base, git(repo, "rev-parse", "HEAD")


def test_review_fails_on_new_escalation(repo: Path, catalog_dir: Path, tmp_path: Path) -> None:
    base, head = commit_change(repo)
    out = tmp_path / "comment.md"
    code = pr_review.main(
        [
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--catalog",
            str(catalog_dir),
            "--comment-file",
            str(out),
            "--fail-on-escalation",
            "--paths",
            "policies/**/*.json",
        ]
    )
    comment = out.read_text()
    assert code == 1
    assert comment.startswith(pr_review.MARKER)
    assert "<code>policies/app.json</code> (modified)" in comment
    assert "<code>policies/new.json</code> (added)" in comment
    assert "<code>policies/old.json</code> (deleted)" in comment
    assert "settings.json" not in comment
    assert "iam-005" in comment
    assert "| ! | <code>iam:PutRolePolicy</code>" in comment


def test_review_passes_without_escalation(repo: Path, catalog_dir: Path, tmp_path: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "policies/app.json", policy("s3:GetObject", "s3:ListBucket"))
    git(repo, "commit", "-qam", "harmless")
    head = git(repo, "rev-parse", "HEAD")
    out = tmp_path / "c.md"
    code = pr_review.main(
        [
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--catalog",
            str(catalog_dir),
            "--comment-file",
            str(out),
            "--fail-on-escalation",
        ]
    )
    assert code == 0
    assert "s3:ListBucket" in out.read_text()


def test_reorder_only_change_reports_no_change(repo: Path, catalog_dir: Path, tmp_path: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    write(
        repo,
        "policies/app.json",
        {"Statement": [{"Resource": ["*"], "Action": "s3:GetObject", "Effect": "Allow"}], "Version": "2012-10-17"},
    )
    git(repo, "commit", "-qam", "reformat")
    head = git(repo, "rev-parse", "HEAD")
    out = tmp_path / "c.md"
    assert (
        pr_review.main(
            [
                "--base",
                base,
                "--head",
                head,
                "--repo",
                str(repo),
                "--catalog",
                str(catalog_dir),
                "--comment-file",
                str(out),
                "--fail-on-diff",
                "any",
            ]
        )
        == 0
    )
    assert "No change in what the policy allows or denies." in out.read_text()


def test_invalid_policy_is_reported_not_fatal(repo: Path, catalog_dir: Path, tmp_path: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    write(
        repo,
        "policies/app.json",
        {"Version": "2012-10-17", "Statement": [{"Effect": "Maybe", "Action": "*", "Resource": "*"}]},
    )
    git(repo, "commit", "-qam", "broken")
    head = git(repo, "rev-parse", "HEAD")
    out = tmp_path / "c.md"
    assert (
        pr_review.main(
            [
                "--base",
                base,
                "--head",
                head,
                "--repo",
                str(repo),
                "--catalog",
                str(catalog_dir),
                "--comment-file",
                str(out),
            ]
        )
        == 0
    )
    assert "Could not analyse" in out.read_text()


def test_comment_neutralises_hostile_policy_content(repo: Path, catalog_dir: Path, tmp_path: Path) -> None:
    base = git(repo, "rev-parse", "HEAD")
    hostile = "arn:aws:s3:::b/`) ![x](https://evil.example/p.png) @security-team | **approved** <img src=x>"
    write(
        repo,
        "policies/app.json",
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"},
                {"Effect": "Allow", "Action": "s3:PutObject", "Resource": [hostile]},
            ],
        },
    )
    git(repo, "commit", "-qam", "hostile")
    head = git(repo, "rev-parse", "HEAD")
    out = tmp_path / "c.md"
    pr_review.main(
        ["--base", base, "--head", head, "--repo", str(repo), "--catalog", str(catalog_dir), "--comment-file", str(out)]
    )
    comment = out.read_text()
    row = next(line for line in comment.splitlines() if "evil.example" in line)
    # The hostile resource is one inert <code> element: no live mention, image, HTML or cell break.
    assert "@security-team" not in comment
    assert "<img" not in comment
    assert "&lt;img" in row and "&#64;security-team" in row and "&#124;" in row
    assert row.count("|") == 7  # exactly the table's own column separators


def test_md_text_escapes_markdown() -> None:
    from iamtrace.diff import md_text

    out = md_text("see [link](https://x) @team <b>")
    assert "@team" not in out and "<b>" not in out and "\\[link\\]" in out


def test_review_reports_only_new_check_findings(repo: Path, tmp_path: Path) -> None:
    from iamtrace.catalog import PACKAGED

    # The base already has a typo; the change keeps it and adds iam:PassRole on every role.
    write(repo, "policies/app.json", policy("s3:GetObjects"))
    git(repo, "commit", "-qam", "typo")
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "policies/app.json", policy("s3:GetObjects", "iam:PassRole"))
    git(repo, "commit", "-qam", "passrole")
    head = git(repo, "rev-parse", "HEAD")
    out = tmp_path / "c.md"
    args = ["--base", base, "--head", head, "--repo", str(repo), "--catalog", str(PACKAGED), "--comment-file", str(out)]
    assert pr_review.main([*args, "--fail-on-check", "medium"]) == 1
    comment = out.read_text()
    assert "New risky patterns: **1**" in comment
    assert "<code>passrole-any-role</code>" in comment
    assert "unknown-action" not in comment
    assert pr_review.main(args) == 0


def test_review_catches_techniques_that_only_work_for_users(repo: Path, catalog_dir: Path, tmp_path: Path) -> None:
    # iam:AttachUserPolicy escalates a user (it attaches AdministratorAccess to itself) but not a role. A
    # policy file in a pull request may be attached to users, so the review must not analyse it as a role only.
    base = git(repo, "rev-parse", "HEAD")
    write(repo, "policies/app.json", policy("s3:GetObject", "iam:AttachUserPolicy"))
    git(repo, "add", "-A")
    git(repo, "commit", "-q", "-m", "user escalation")
    head = git(repo, "rev-parse", "HEAD")
    out = tmp_path / "comment.md"
    code = pr_review.main(
        [
            "--base",
            base,
            "--head",
            head,
            "--repo",
            str(repo),
            "--catalog",
            str(catalog_dir),
            "--comment-file",
            str(out),
            "--fail-on-escalation",
            "--paths",
            "policies/**/*.json",
        ]
    )
    assert code == 1
    assert "iam-008" in out.read_text()


def test_escalation_techniques_lists_each_technique_once() -> None:
    from iamtrace.model import Policy, PolicyType

    pol = Policy.parse(
        policy("iam:PutRolePolicy", "iam:AttachUserPolicy", "iam:CreateAccessKey"),
        policy_id="p",
        policy_type=PolicyType.IDENTITY,
    )
    ids = [t["id"] for t in pr_review.escalation_techniques(pol)]
    assert len(ids) == len(set(ids))
    assert {"iam-005", "iam-008", "iam-002"} <= set(ids)
