"""Pull-request review used by the GitHub Action (action/action.yml).

For every changed policy file between two git revisions it builds the semantic diff and, for
identity policies, the escalation techniques that are new compared with the base version. It
renders one Markdown comment and decides whether the check should fail.

    python -m iamtrace.pr_review --base SHA --head SHA --paths '**/*.json' [--fail-on-escalation]
                                [--fail-on-diff highlighted] [--comment-file out.md]

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
from iamtrace.diff import diff_markdown, diff_policies, md_code, md_text
from iamtrace.escalate import Environment, analyze
from iamtrace.loader import parse_any_policy
from iamtrace.model import Policy, PolicyError, PolicyType

MARKER = "<!-- iamtrace-pr-review -->"
PRINCIPAL = "arn:aws:iam::111122223333:role/policy-under-review"


@dataclass
class FileReport:
    path: str
    status: str  # added | modified | deleted
    diff: dict[str, Any] | None = None
    new_escalations: list[dict[str, Any]] = field(default_factory=list)
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
            now = analyze(Environment.single([new_id], PRINCIPAL), start=PRINCIPAL)
            before_ids: set[str] = set()
            old_id = _identity(old)
            if old_id is not None:
                before = analyze(Environment.single([old_id], PRINCIPAL), start=PRINCIPAL)
                before_ids = {t["id"] for p in before["principals"] for t in p["techniques"]}
            rep.new_escalations = [t for p in now["principals"] for t in p["techniques"] if t["id"] not in before_ids]
    except PolicyError as e:
        rep.error = str(e)
    return rep


def render(reports: list[FileReport]) -> str:
    lines = [MARKER, "### iam-trace policy review", ""]
    if not reports:
        return "\n".join(lines + ["No IAM policy files changed."]) + "\n"
    escalations = sum(len(r.new_escalations) for r in reports)
    highlighted = sum(r.diff["highlighted"] for r in reports if r.diff)
    lines.append(
        f"{len(reports)} policy file(s) changed. New escalation techniques: **{escalations}**. "
        f"Newly allowed sensitive actions: **{highlighted}**."
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
    if any(r.error for r in reports):
        print("::warning::some policy files could not be analysed", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
