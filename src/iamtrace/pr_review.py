"""Pull-request review used by the GitHub Action (action/action.yml).

For every changed policy file between two git revisions it builds the semantic diff and, for
identity policies, the escalation techniques that are new compared with the base version. It
also runs Policy check (iamtrace.check) on both versions and reports only the findings the change
introduces, so a pull request is not blamed for problems that were already there. It renders one
Markdown comment and decides whether the check should fail.

    python -m iamtrace.pr_review --base SHA --head SHA --paths '**/*.json' [--fail-on-escalation]
                                [--fail-on-diff highlighted] [--fail-on-check high] [--comment-file out.md]

Posting the comment is done by the workflow step with the GitHub CLI, so this module needs no
token and makes no network calls.
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from iamtrace.catalog import Catalog
from iamtrace.check import check_documents
from iamtrace.diff import diff_markdown, diff_policies, md_code, md_text
from iamtrace.escalate import Environment, analyze
from iamtrace.loader import parse_any_policy
from iamtrace.model import Policy, PolicyError, PolicyType

MARKER = "<!-- iamtrace-pr-review -->"
# A changed policy can be attached to roles or to users, and some techniques only work for one of them
# (iam:AttachUserPolicy and iam:AddUserToGroup escalate a user, not a role). It is analysed as both.
PRINCIPALS = (
    "arn:aws:iam::111122223333:role/policy-under-review",
    "arn:aws:iam::111122223333:user/policy-under-review",
)


@dataclass
class FileReport:
    path: str
    status: str  # added | modified | deleted
    diff: dict[str, Any] | None = None
    new_escalations: list[dict[str, Any]] = field(default_factory=list)
    new_checks: list[dict[str, Any]] = field(default_factory=list)
    error: str | None = None


def git(*args: str, cwd: Path) -> str:
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True).stdout


def changed_files(base: str, head: str, patterns: list[str], cwd: Path) -> list[tuple[str, str]]:
    out = git("diff", "--name-status", "--no-renames", f"{base}...{head}", cwd=cwd)
    files = []
    for line in out.splitlines():
        status, _, path = line.partition("\t")
        if any(fnmatch.fnmatch(path, p) for p in patterns):
            files.append(({"A": "added", "D": "deleted"}.get(status[:1], "modified"), path))
    return files


def show(rev: str, path: str, cwd: Path) -> str | None:
    try:
        return git("show", f"{rev}:{path}", cwd=cwd)
    except subprocess.CalledProcessError:
        return None


def looks_like_policy(text: str | None) -> bool:
    if not text:
        return False
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return False
    return isinstance(doc, dict) and "Statement" in doc


def _identity(policy: Policy | None) -> Policy | None:
    """Escalation analysis only makes sense for identity policies (no Principal element)."""
    if policy is None or policy.type is not PolicyType.IDENTITY:
        return None
    return policy


def escalation_techniques(policy: Policy) -> list[dict[str, Any]]:
    """Techniques the policy allows when attached to a role or to a user, each listed once."""
    seen: dict[str, dict[str, Any]] = {}
    for arn in PRINCIPALS:
        report = analyze(Environment.single([policy], arn), start=arn)
        for p in report["principals"]:
            for t in p["techniques"]:
                seen.setdefault(t["id"], t)
    return list(seen.values())


def review_file(path: str, status: str, old_text: str | None, new_text: str | None, cat: Catalog) -> FileReport | None:
    if not looks_like_policy(old_text) and not looks_like_policy(new_text):
        return None  # a JSON file that is not a policy document
    rep = FileReport(path, status)
    try:
        old = parse_any_policy(old_text, f"{path} (base)") if old_text and looks_like_policy(old_text) else None
        new = parse_any_policy(new_text, path) if new_text and looks_like_policy(new_text) else None
        rep.diff = diff_policies(old, new, cat)
        new_id = _identity(new)
        if new_id is not None:
            before_ids: set[str] = set()
            old_id = _identity(old)
            if old_id is not None:
                before_ids = {t["id"] for t in escalation_techniques(old_id)}
            rep.new_escalations = [t for t in escalation_techniques(new_id) if t["id"] not in before_ids]
        if new is not None and new_text is not None:
            rep.new_checks = new_check_findings(path, old_text if old is not None else None, new_text, cat)
    except PolicyError as e:
        rep.error = str(e)
    return rep


def new_check_findings(path: str, old_text: str | None, new_text: str, cat: Catalog) -> list[dict[str, Any]]:
    """Policy check findings in the new version that the old version did not have. A finding is
    the same if its rule, statement and detail match; both versions are checked under one name so
    the policy name in the detail cannot differ."""

    def key(f: dict[str, Any]) -> tuple[str, str, str]:
        return (f["rule"], f["statement"], f["detail"])

    before = {key(f) for f in check_documents([(path, old_text)], cat)["findings"]} if old_text else set()
    return [f for f in check_documents([(path, new_text)], cat)["findings"] if key(f) not in before]


def render(reports: list[FileReport]) -> str:
    lines = [MARKER, "### iam-trace policy review", ""]
    if not reports:
        return "\n".join(lines + ["No IAM policy files changed."]) + "\n"
    escalations = sum(len(r.new_escalations) for r in reports)
    highlighted = sum(r.diff["highlighted"] for r in reports if r.diff)
    checks = sum(len(r.new_checks) for r in reports)
    lines.append(
        f"{len(reports)} policy file(s) changed. New escalation techniques: **{escalations}**. "
        f"Newly allowed sensitive actions: **{highlighted}**. New risky patterns: **{checks}**."
    )
    for r in reports:
        lines += ["", "---", ""]
        if r.error:
            lines += [f"#### {md_code(r.path)} ({r.status})", "", f"Could not analyse: {md_text(r.error)}"]
            continue
        assert r.diff is not None
        lines.append(diff_markdown(r.diff, f"{md_code(r.path)} ({r.status})").rstrip())
        if r.new_escalations:
            lines += ["", "**New privilege-escalation techniques this policy allows**", ""]
            for t in r.new_escalations:
                lines.append(f"- [{t['id']}]({t['source']['pathfinding']}) `{t['name']}` ({t['category']})")
        if r.new_checks:
            lines += ["", "**New risky patterns** (iam-trace check)", ""]
            for f in r.new_checks:
                where = f" in {md_text(f['statement'])}" if f["statement"] else ""
                lines.append(
                    f"- **{f['severity'].capitalize()}** {md_code(f['rule'])}{where}: {md_text(f['detail'], 400)} "
                    f"Fix: {md_text(f['fix'], 400)}"
                )
    lines += [
        "",
        "<sub>Generated by iam-trace. A ! marks permissions-management actions and actions used in known "
        "escalation paths. Escalation analysis treats each identity policy as the only policy of one role.</sub>",
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--base", required=True)
    ap.add_argument("--head", required=True)
    ap.add_argument("--paths", default="**/*.json", help="comma-separated glob patterns of policy files")
    ap.add_argument("--repo", default=".")
    ap.add_argument("--catalog")
    ap.add_argument("--comment-file", default="iamtrace-comment.md")
    ap.add_argument("--fail-on-escalation", action="store_true")
    ap.add_argument("--fail-on-diff", choices=["never", "any", "new-allow", "highlighted"], default="never")
    ap.add_argument(
        "--fail-on-check",
        choices=["never", "high", "medium", "low"],
        default="never",
        help="fail when the change introduces a Policy check finding at this severity or higher",
    )
    args = ap.parse_args(argv)

    cwd = Path(args.repo)
    cat = Catalog.load(args.catalog)
    patterns = [p.strip() for p in args.paths.split(",") if p.strip()]
    # fnmatch's "*" already crosses "/", so "**/" adds nothing; also match files at the root.
    patterns += [p.replace("**/", "") for p in patterns if "**/" in p]
    reports = []
    for status, path in changed_files(args.base, args.head, patterns, cwd):
        old = None if status == "added" else show(args.base, path, cwd)
        new = None if status == "deleted" else show(args.head, path, cwd)
        rep = review_file(path, status, old, new, cat)
        if rep:
            reports.append(rep)
    Path(args.comment_file).write_text(render(reports))
    print(render(reports))

    failed = False
    if args.fail_on_escalation and any(r.new_escalations for r in reports):
        print("::error::the change allows new privilege-escalation techniques", file=sys.stderr)
        failed = True
    diffs = [r.diff for r in reports if r.diff]
    if args.fail_on_diff == "any" and any(not d["unchanged"] for d in diffs):
        failed = True
    if args.fail_on_diff == "new-allow" and any(d["changes"]["newly_allowed"] for d in diffs):
        failed = True
    if args.fail_on_diff == "highlighted" and any(d["highlighted"] for d in diffs):
        failed = True
    if args.fail_on_check != "never":
        levels = ["high", "medium", "low"]
        worst = set(levels[: levels.index(args.fail_on_check) + 1])
        if any(f["severity"] in worst for r in reports for f in r.new_checks):
            print(
                f"::error::the change introduces {args.fail_on_check}-severity risky patterns or worse", file=sys.stderr
            )
            failed = True
    if any(r.error for r in reports):
        print("::warning::some policy files could not be analysed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
