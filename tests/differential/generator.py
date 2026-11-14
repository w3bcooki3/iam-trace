"""Generate policy/request pairs for the differential test against the AWS policy simulator.

Each case is a plain dict that both sides can consume:

    {
      "id": "arn-wildcards-007",
      "category": "arn_wildcards",
      "note": "why this case exists",
      "identity": [policy, ...],          # PolicyInputList
      "boundary": policy | None,          # PermissionsBoundaryPolicyInputList (one only)
      "resource_policy": policy | None,   # ResourcePolicy
      "resource_owner": "{OTHER}" | None, # ResourceOwner account, for cross-account cases
      "scps": [[policy], ...] | None,     # OrderedOrganizationPolicyInputList, root first
      "action": "s3:GetObject",
      "resource": "arn:aws:s3:::bucket/key",
      "context": {"key": {"type": "string", "values": ["v"]}},
    }

"{ACCOUNT}" stands for the account the simulator runs in and "{OTHER}" for a second account.
The caller is the IAM user or role the runner is configured with (see runner.py).

The categories are the ones listed in the project brief, plus a few cases the AWS docs leave
undocumented (marked "undocumented" in their note).

Run `python -m tests.differential.generator --count` to see how many cases exist.
"""

from __future__ import annotations

import argparse
import itertools
from typing import Any

V = "2012-10-17"


def doc(*statements: dict[str, Any], version: str | None = V) -> dict[str, Any]:
    d: dict[str, Any] = {"Statement": list(statements)}
    if version:
        d["Version"] = version
    return d


def st(effect: str, action: Any = None, resource: Any = "*", **extra: Any) -> dict[str, Any]:
    s: dict[str, Any] = {"Effect": effect}
    if action is not None:
        s["Action"] = action
    if resource is not None:
        s["Resource"] = resource
    s.update(extra)
    return s


def ctx(**typed: tuple[str, list[str]]) -> dict[str, Any]:
    return {k.replace("__", ":").replace("_SLASH_", "/"): {"type": t, "values": v} for k, (t, v) in typed.items()}


class Builder:
    def __init__(self) -> None:
        self.cases: list[dict[str, Any]] = []
        self._counters: dict[str, itertools.count[int]] = {}

    def add(
        self,
        category: str,
        note: str,
        *,
        action: str,
        resource: str,
        identity: list[dict[str, Any]] | None = None,
        boundary: dict[str, Any] | None = None,
        resource_policy: dict[str, Any] | None = None,
        resource_owner: str | None = None,
        scps: list[list[dict[str, Any]]] | None = None,
        context: dict[str, Any] | None = None,
    ) -> None:
        n = next(self._counters.setdefault(category, itertools.count(1)))
        self.cases.append(
            {
                "id": f"{category.replace('_', '-')}-{n:03d}",
                "category": category,
                "note": note,
                "identity": identity if identity is not None else [],
                "boundary": boundary,
                "resource_policy": resource_policy,
                "resource_owner": resource_owner,
                "scps": scps,
                "action": action,
                "resource": resource,
                "context": context or {},
            }
        )


def generate() -> list[dict[str, Any]]:
    b = Builder()
    _notaction_deny(b)
    _arn_wildcards(b)
    _if_exists(b)
    _for_all_values(b)
    _variables(b)
    _boundaries(b)
    _cross_account(b)
    _scps(b)
    _undocumented(b)
    return b.cases


# --- categories --------------------------------------------------------------------


def _notaction_deny(b: Builder) -> None:
    not_actions = ["s3:*", "s3:Get*", "iam:*", "ec2:Describe*", ["s3:GetObject", "iam:List*"]]
    actions = [
        ("s3:GetObject", "arn:aws:s3:::bucket/key"),
        ("s3:PutObject", "arn:aws:s3:::bucket/key"),
        ("iam:GetUser", "*"),
        ("iam:ListUsers", "*"),
        ("ec2:DescribeInstances", "*"),
        ("ec2:RunInstances", "*"),
    ]
    for na in not_actions:
        for action, res in actions:
            b.add(
                "notaction_deny",
                f"Allow *, Deny NotAction {na}",
                action=action,
                resource=res,
                identity=[doc(st("Allow", "*"), st("Deny", resource="*", NotAction=na))],
            )
    # NotAction in an Allow combined with NotResource.
    for action, res in actions[:3]:
        b.add(
            "notaction_deny",
            "Allow NotAction iam:* on NotResource bucket/secret/*",
            action=action,
            resource=res,
            identity=[doc(st("Allow", resource=None, NotAction="iam:*", NotResource="arn:aws:s3:::bucket/secret/*"))],
        )


def _arn_wildcards(b: Builder) -> None:
    patterns = [
        "arn:aws:s3:::bucket*",
        "arn:aws:s3:::bucket/*",
        "arn:aws:s3:::*log*",
        "arn:aws:s3:::bucket/?.txt",
        "arn:aws:s3:::*/*",
        "arn:aws:s3:::bucket/a*b",
        "arn:aws:s3:::BUCKET/*",
    ]
    resources = [
        "arn:aws:s3:::bucket",
        "arn:aws:s3:::bucket/key",
        "arn:aws:s3:::bucket/a.txt",
        "arn:aws:s3:::bucket/dir/ab",
        "arn:aws:s3:::my-logs/x",
    ]
    for p in patterns:
        for r in resources:
            b.add(
                "arn_wildcards",
                f"Resource {p}",
                action="s3:GetObject",
                resource=r,
                identity=[doc(st("Allow", "s3:GetObject", p))],
            )
    q = "arn:aws:sqs:us-east-1:{ACCOUNT}:queue1"
    for p in [
        "arn:aws:sqs:*:{ACCOUNT}:queue*",
        "arn:aws:sqs:us-*:*:queue?",
        "arn:aws:sqs:*:*:*",
        "arn:aws:sqs:*",
        "arn:aws:*",
        "arn:aws:sqs:us-east-1:*",
        "arn:*:sqs:*:*:queue1",
        "arn:aws:sqs:us-east-1:{ACCOUNT}:*1",
    ]:
        note = f"Resource {p}"
        if p.count(":") < 5:
            note += " (undocumented: fewer than six ARN components)"
        b.add(
            "arn_wildcards",
            note,
            action="sqs:SendMessage",
            resource=q,
            identity=[doc(st("Allow", "sqs:SendMessage", p))],
        )
    # Action wildcards.
    for a in ["s3:Get*", "s3:*Object", "s3:Get?bject", "S3:GETOBJECT", "s3:*"]:
        b.add(
            "arn_wildcards",
            f"Action {a}",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/key",
            identity=[doc(st("Allow", a))],
        )


def _if_exists(b: Builder) -> None:
    cases = [
        ("StringEqualsIfExists", "ec2:InstanceType", "string", ["t2.micro"], "t2.micro"),
        ("StringLikeIfExists", "ec2:InstanceType", "string", ["t2.*"], "m5.large"),
        ("StringNotEqualsIfExists", "ec2:InstanceType", "string", ["t2.micro"], "t2.micro"),
        ("NumericLessThanIfExists", "s3:max-keys", "numeric", ["10"], "5"),
        ("BoolIfExists", "aws:MultiFactorAuthPresent", "boolean", ["true"], "false"),
        ("ArnLikeIfExists", "aws:SourceArn", "string", ["arn:aws:sns:*:*:t"], "arn:aws:sns:us-east-1:1:t"),
        ("IpAddressIfExists", "aws:SourceIp", "ip", ["10.0.0.0/8"], "192.0.2.1"),
        ("DateGreaterThanIfExists", "aws:CurrentTime", "date", ["2020-01-01T00:00:00Z"], "2024-01-01T00:00:00Z"),
    ]
    for op, key, ctype, values, present in cases:
        for effect in ("Allow", "Deny"):
            identity = (
                [doc(st("Allow", "*"), st("Deny", "*", Condition={op: {key: values}}))]
                if effect == "Deny"
                else [doc(st("Allow", "*", Condition={op: {key: values}}))]
            )
            for with_key in (False, True):
                context = {key: {"type": ctype, "values": [present]}} if with_key else {}
                b.add(
                    "if_exists",
                    f"{effect} with {op} {key}, key {'present' if with_key else 'absent'}",
                    action="ec2:RunInstances",
                    resource="*",
                    identity=identity,
                    context=context,
                )


def _for_all_values(b: Builder) -> None:
    contexts: list[tuple[str, dict[str, Any] | None]] = [
        ("absent", None),
        ("empty", {"aws:TagKeys": {"type": "stringList", "values": []}}),
        ("subset", {"aws:TagKeys": {"type": "stringList", "values": ["env"]}}),
        ("equal", {"aws:TagKeys": {"type": "stringList", "values": ["env", "team"]}}),
        ("superset", {"aws:TagKeys": {"type": "stringList", "values": ["env", "owner"]}}),
    ]
    conds = [
        ("ForAllValues:StringEquals", {"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team"]}}),
        ("ForAnyValue:StringEquals", {"ForAnyValue:StringEquals": {"aws:TagKeys": ["env", "team"]}}),
        (
            "ForAllValues:StringEquals + Null false",
            {"ForAllValues:StringEquals": {"aws:TagKeys": ["env", "team"]}, "Null": {"aws:TagKeys": "false"}},
        ),
        ("ForAllValues:StringNotEquals", {"ForAllValues:StringNotEquals": {"aws:TagKeys": ["owner"]}}),
    ]
    for (name, cond), (cname, context) in itertools.product(conds, contexts):
        note = f"Allow with {name}, tag keys {cname}"
        if cname == "empty":
            note += " (the simulator may reject an empty list; recorded as an error if so)"
        b.add(
            "for_all_values",
            note,
            action="ec2:CreateTags",
            resource="*",
            identity=[doc(st("Allow", "ec2:CreateTags", Condition=cond))],
            context=context,
        )
    for cname, context in contexts:
        b.add(
            "for_all_values",
            f"Deny with ForAnyValue:StringEquals, tag keys {cname}",
            action="ec2:CreateTags",
            resource="*",
            identity=[
                doc(
                    st("Allow", "*"),
                    st("Deny", "*", Condition={"ForAnyValue:StringEquals": {"aws:TagKeys": ["owner"]}}),
                )
            ],
            context=context,
        )


def _variables(b: Builder) -> None:
    # The runner fills in the caller's user name for {USERNAME}.
    own = "arn:aws:s3:::bucket/home/{USERNAME}/file"
    other = "arn:aws:s3:::bucket/home/someone-else/file"
    for res in (own, other):
        b.add(
            "variables",
            "Resource with ${aws:username}",
            action="s3:GetObject",
            resource=res,
            identity=[doc(st("Allow", "s3:GetObject", "arn:aws:s3:::bucket/home/${aws:username}/*"))],
        )
        b.add(
            "variables",
            "Resource with ${aws:username}, no Version: literal",
            action="s3:GetObject",
            resource=res,
            identity=[doc(st("Allow", "s3:GetObject", "arn:aws:s3:::bucket/home/${aws:username}/*"), version=None)],
        )
    tag_ctx = {"aws:PrincipalTag/team": {"type": "string", "values": ["blue"]}}
    for context, label in ((tag_ctx, "tag present"), ({}, "tag absent")):
        for res in ("arn:aws:s3:::bucket/blue/x", "arn:aws:s3:::bucket/company-wide/x"):
            b.add(
                "variables",
                f"Resource with default value, {label}",
                action="s3:GetObject",
                resource=res,
                identity=[
                    doc(st("Allow", "s3:GetObject", "arn:aws:s3:::bucket/${aws:PrincipalTag/team, 'company-wide'}/*"))
                ],
                context=context,
            )
        b.add(
            "variables",
            f"StringNotEquals with missing variable, {label}",
            action="s3:GetObject",
            resource="arn:aws:s3:::bucket/x",
            identity=[
                doc(
                    st("Allow", "*"),
                    st(
                        "Deny",
                        "s3:*",
                        Condition={"StringNotEquals": {"s3:ExistingObjectTag/team": "${aws:PrincipalTag/team}"}},
                    ),
                )
            ],
            context={**context, "s3:ExistingObjectTag/team": {"type": "string", "values": ["blue"]}},
        )
    for res in ("arn:aws:s3:::bucket/*", "arn:aws:s3:::bucket/x"):
        b.add(
            "variables",
            "Resource with ${*} escape",
            action="s3:GetObject",
            resource=res,
            identity=[doc(st("Allow", "s3:GetObject", "arn:aws:s3:::bucket/${*}"))],
        )
    for prefix in ("home/{USERNAME}/", "home/other/"):
        b.add(
            "variables",
            "StringLike condition with ${aws:username}",
            action="s3:ListBucket",
            resource="arn:aws:s3:::bucket",
            identity=[
                doc(
                    st(
                        "Allow",
                        "s3:ListBucket",
                        "arn:aws:s3:::bucket",
                        Condition={"StringLike": {"s3:prefix": ["home/${aws:username}/*"]}},
                    )
                )
            ],
            context={"s3:prefix": {"type": "string", "values": [prefix + "x"]}},
        )


def _boundaries(b: Builder) -> None:
    identities = {
        "allow s3:*": doc(st("Allow", "s3:*")),
        "allow *": doc(st("Allow", "*")),
        "allow ec2:*": doc(st("Allow", "ec2:*")),
    }
    boundaries = {
        "allow s3:Get*": doc(st("Allow", "s3:Get*")),
        "allow * deny s3:Put*": doc(st("Allow", "*"), st("Deny", "s3:Put*")),
        "allow NotResource secret": doc(st("Allow", "s3:*", resource=None, NotResource="arn:aws:s3:::bucket/secret/*")),
        "allow s3 with MFA": doc(st("Allow", "s3:*", Condition={"Bool": {"aws:MultiFactorAuthPresent": "true"}})),
    }
    requests = [
        ("s3:GetObject", "arn:aws:s3:::bucket/key"),
        ("s3:PutObject", "arn:aws:s3:::bucket/key"),
        ("s3:GetObject", "arn:aws:s3:::bucket/secret/x"),
    ]
    for (iname, ident), (bname, bnd), (action, res) in itertools.product(
        identities.items(), boundaries.items(), requests
    ):
        if iname == "allow ec2:*" and action != "s3:GetObject":
            continue
        b.add(
            "boundaries",
            f"identity {iname}, boundary {bname}",
            action=action,
            resource=res,
            identity=[ident],
            boundary=bnd,
        )


def _cross_account(b: Builder) -> None:
    obj = "arn:aws:s3:::other-bucket/key"
    principals = {
        "caller ARN": {"AWS": "{CALLER}"},
        "caller account": {"AWS": "{ACCOUNT}"},
        "caller account root": {"AWS": "arn:aws:iam::{ACCOUNT}:root"},
        "another account": {"AWS": "222233334444"},
        "everyone": "*",
    }
    for (pname, principal), with_identity, owner in itertools.product(
        principals.items(), (True, False), ("{OTHER}", None)
    ):
        rp = doc(st("Allow", "s3:GetObject", obj, Principal=principal))
        where = "cross-account" if owner else "same-account"
        b.add(
            "cross_account",
            f"{where}: bucket policy grants {pname}, identity {'allows' if with_identity else 'silent'}",
            action="s3:GetObject",
            resource=obj,
            resource_policy=rp,
            resource_owner=owner,
            identity=[doc(st("Allow", "s3:*"))] if with_identity else [doc(st("Allow", "ec2:DescribeInstances"))],
        )
    # Explicit deny on either side.
    b.add(
        "cross_account",
        "cross-account: bucket policy denies the caller",
        action="s3:GetObject",
        resource=obj,
        resource_policy=doc(
            st("Allow", "s3:*", obj, Principal="*"), st("Deny", "s3:GetObject", obj, Principal={"AWS": "{CALLER}"})
        ),
        resource_owner="{OTHER}",
        identity=[doc(st("Allow", "s3:*"))],
    )
    b.add(
        "cross_account",
        "cross-account: identity denies",
        action="s3:GetObject",
        resource=obj,
        resource_policy=doc(st("Allow", "s3:*", obj, Principal="*")),
        resource_owner="{OTHER}",
        identity=[doc(st("Allow", "*"), st("Deny", "s3:GetObject"))],
    )
    b.add(
        "cross_account",
        "cross-account: boundary limits identity side",
        action="s3:GetObject",
        resource=obj,
        resource_policy=doc(st("Allow", "s3:*", obj, Principal={"AWS": "{CALLER}"})),
        resource_owner="{OTHER}",
        identity=[doc(st("Allow", "s3:*"))],
        boundary=doc(st("Allow", "ec2:*")),
    )
    b.add(
        "cross_account",
        "same-account: caller ARN grant not limited by boundary",
        action="s3:GetObject",
        resource=obj,
        resource_policy=doc(st("Allow", "s3:*", obj, Principal={"AWS": "{CALLER}"})),
        identity=[doc(st("Allow", "ec2:*"))],
        boundary=doc(st("Allow", "ec2:*")),
    )


def _scps(b: Builder) -> None:
    levels = {
        "root allows *": [[doc(st("Allow", "*"))]],
        "root allows *, OU allows ec2:*": [[doc(st("Allow", "*"))], [doc(st("Allow", "ec2:*"))]],
        "root allows *, account denies s3:Put*": [
            [doc(st("Allow", "*"))],
            [doc(st("Allow", "*"), st("Deny", "s3:Put*"))],
        ],
        "root allows * with region condition": [
            [doc(st("Allow", "*", Condition={"StringEquals": {"aws:RequestedRegion": "us-east-1"}}))]
        ],
    }
    for (name, scps), action in itertools.product(levels.items(), ("s3:GetObject", "s3:PutObject", "ec2:RunInstances")):
        b.add(
            "scps",
            f"SCPs: {name}",
            action=action,
            resource="*",
            identity=[doc(st("Allow", "*"))],
            scps=scps,
            context={"aws:RequestedRegion": {"type": "string", "values": ["us-east-1"]}},
        )


def _undocumented(b: Builder) -> None:
    # A single-value operator on a multivalued key.
    for values in (["env"], ["env", "team"], ["owner", "env"]):
        b.add(
            "undocumented",
            f"undocumented: StringEquals on multivalued aws:TagKeys={values}",
            action="ec2:CreateTags",
            resource="*",
            identity=[doc(st("Allow", "ec2:CreateTags", Condition={"StringEquals": {"aws:TagKeys": "env"}}))],
            context={"aws:TagKeys": {"type": "stringList", "values": values}},
        )
    # Negated numeric/date/IP operators with a missing key.
    for op, key in (
        ("NumericNotEquals", "s3:max-keys"),
        ("DateNotEquals", "aws:EpochTime"),
        ("NotIpAddress", "aws:VpcSourceIp"),
    ):
        b.add(
            "undocumented",
            f"undocumented: {op} with the key absent",
            action="s3:ListBucket",
            resource="arn:aws:s3:::bucket",
            identity=[
                doc(st("Allow", "s3:ListBucket", Condition={op: {key: "1" if "Ip" not in op else "10.0.0.0/8"}}))
            ],
        )
    # Wildcards in the Resource element crossing a colon in the resource part.
    lg = "arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/app/web:log-stream:s1"
    for p in ("arn:aws:logs:us-east-1:{ACCOUNT}:log-group:/app/*", "arn:aws:logs:*:{ACCOUNT}:log-group:*:log-stream:*"):
        b.add(
            "undocumented",
            f"undocumented: resource-part wildcard across ':' ({p})",
            action="logs:PutLogEvents",
            resource=lg,
            identity=[doc(st("Allow", "logs:PutLogEvents", p))],
        )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--count", action="store_true")
    args = parser.parse_args()
    cases = generate()
    if args.count:
        by_cat: dict[str, int] = {}
        for c in cases:
            by_cat[c["category"]] = by_cat.get(c["category"], 0) + 1
        for k, v in sorted(by_cat.items()):
            print(f"{k:<16} {v}")
        print(f"{'total':<16} {len(cases)}")


if __name__ == "__main__":
    main()
