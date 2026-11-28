"""CloudFormation templates: review IAM changes before a stack is created or updated.

Input is a template in YAML or JSON, and optionally the template the stack runs now. Every IAM-relevant
resource is read:

- AWS::IAM::Role (trust policy, Policies, ManagedPolicyArns), AWS::IAM::User and AWS::IAM::Group
  (Policies, ManagedPolicyArns, Groups), AWS::IAM::ManagedPolicy (with its Roles, Users and Groups),
  AWS::IAM::Policy and AWS::IAM::RolePolicy / UserPolicy / GroupPolicy (inline),
  AWS::IAM::UserToGroupAddition,
- AWS::S3::BucketPolicy and AWS::KMS::Key (resource policies).

Intrinsic functions are resolved the way CloudFormation would for this stack: Ref and Fn::GetAtt to the
template's own resources (their names, or the names CloudFormation would generate), parameters (from
--parameter, else their defaults), pseudo parameters, Fn::Sub, Fn::Join, Fn::Select, Fn::Split,
Fn::FindInMap, and Fn::If with the template's Conditions; a resource whose Condition is false is left out.
What cannot be known before deployment (Fn::ImportValue, a parameter with no value) is kept as a visible
placeholder such as ${Import:SharedBucket} and listed in the notes, never guessed.

The template is then turned into the same shape as a Terraform plan and reviewed by iamtrace.terraform:
the document diffs, new escalation techniques and risky patterns, and with the account export, the paths
to admin, admins and entry points the stack would add.
"""

from __future__ import annotations

import json
import re
from typing import Any

from iamtrace.catalog import Catalog
from iamtrace.cfnyaml import YamlError, loads
from iamtrace.terraform import TerraformError
from iamtrace.terraform import review as plan_review

NO_VALUE = object()

# Ref and the Arn attribute of the resource types a policy names most often.
# The property that names a resource, and its Fn::GetAtt Arn.
ARNS: dict[str, tuple[str, str]] = {
    # resource type -> (property that names it, ARN pattern with {name} {region} {account} {partition})
    "AWS::S3::Bucket": ("BucketName", "arn:{partition}:s3:::{name}"),
    "AWS::SQS::Queue": ("QueueName", "arn:{partition}:sqs:{region}:{account}:{name}"),
    "AWS::SNS::Topic": ("TopicName", "arn:{partition}:sns:{region}:{account}:{name}"),
    "AWS::DynamoDB::Table": ("TableName", "arn:{partition}:dynamodb:{region}:{account}:table/{name}"),
    "AWS::Lambda::Function": ("FunctionName", "arn:{partition}:lambda:{region}:{account}:function:{name}"),
    "AWS::SecretsManager::Secret": ("Name", "arn:{partition}:secretsmanager:{region}:{account}:secret:{name}"),
    "AWS::Logs::LogGroup": ("LogGroupName", "arn:{partition}:logs:{region}:{account}:log-group:{name}"),
    "AWS::ECR::Repository": ("RepositoryName", "arn:{partition}:ecr:{region}:{account}:repository/{name}"),
    "AWS::StepFunctions::StateMachine": (
        "StateMachineName",
        "arn:{partition}:states:{region}:{account}:stateMachine:{name}",
    ),
    "AWS::Kinesis::Stream": ("Name", "arn:{partition}:kinesis:{region}:{account}:stream/{name}"),
}


class TemplateError(ValueError):
    """Not a CloudFormation template that can be read."""


class _Stack:
    """One template, resolved for one stack."""

    def __init__(self, tpl: Any, label: str, params: dict[str, str], account: str, region: str, stack: str) -> None:
        if not isinstance(tpl, dict) or not isinstance(tpl.get("Resources"), dict):
            raise TemplateError(f"{label}: not a CloudFormation template (no Resources section)")
        if tpl.get("Transform"):
            t = tpl["Transform"]
            names = t if isinstance(t, list) else [t]
            if any(isinstance(x, str) and x.startswith("AWS::Serverless") for x in names):
                raise TemplateError(
                    f"{label}: a SAM template (Transform: AWS::Serverless). Review the processed template instead: "
                    "sam build, then the template in .aws-sam/build, "
                    "or aws cloudformation get-template --template-stage Processed"
                )
        self.tpl, self.label = tpl, label
        self.pseudo = {
            "AWS::AccountId": account,
            "AWS::Region": region,
            "AWS::Partition": "aws",
            "AWS::StackName": stack,
            "AWS::StackId": f"arn:aws:cloudformation:{region}:{account}:stack/{stack}/"
            + "0" * 8
            + "-0000-0000-0000-"
            + "0" * 12,
            "AWS::URLSuffix": "amazonaws.com",
            "AWS::NotificationARNs": [],
        }
        self.stack = stack
        self.notes: list[str] = []
        self.params: dict[str, Any] = {}
        for name, p in (tpl.get("Parameters") or {}).items():
            if not isinstance(p, dict):
                continue
            if name in params:
                v: Any = params[name]
            elif "Default" in p:
                v = p["Default"]
            else:
                v = f"${{{name}}}"
                self.notes.append(f"{label}: parameter {name} has no value or default; it is shown as ${{{name}}}.")
            if str(p.get("Type", "")).startswith("List<") or p.get("Type") == "CommaDelimitedList":
                v = [x.strip() for x in v.split(",")] if isinstance(v, str) else v
            self.params[name] = v
        for name in params:
            if name not in self.params:
                self.notes.append(f"{label}: --parameter {name} is not a parameter of this template; ignored.")
        self.resources: dict[str, dict[str, Any]] = {k: v for k, v in tpl["Resources"].items() if isinstance(v, dict)}
        self._conds: dict[str, bool] = {}
        self._depth = 0
        self._naming: set[str] = set()

    # -- names CloudFormation gives
    def physical(self, logical: str) -> str:
        r = self.resources.get(logical) or {}
        props = r.get("Properties") or {}
        t = r.get("Type", "")
        key = {
            "AWS::IAM::Role": "RoleName",
            "AWS::IAM::User": "UserName",
            "AWS::IAM::Group": "GroupName",
            "AWS::IAM::ManagedPolicy": "ManagedPolicyName",
            "AWS::IAM::InstanceProfile": "InstanceProfileName",
        }.get(t) or ARNS.get(t, ("", ""))[0]
        if key and key in props and logical not in self._naming:
            self._naming.add(logical)  # a name that refers to the resource itself is not resolved in a loop
            try:
                v = self.value(props[key])
            finally:
                self._naming.discard(logical)
            if isinstance(v, str):
                return v
        # CloudFormation's own pattern is <stack>-<logical ID>-<random suffix>; the suffix is not known in advance
        return f"{self.stack}-{logical}"

    def _ref(self, name: Any) -> Any:
        if not isinstance(name, str):
            return "${Ref}"
        if name == "AWS::NoValue":
            return NO_VALUE
        if name in self.pseudo:
            return self.pseudo[name]
        if name in self.params:
            return self.params[name]
        r = self.resources.get(name)
        if r is None:
            self.notes.append(f"{self.label}: Ref {name} names nothing in the template; shown as ${{{name}}}.")
            return f"${{{name}}}"
        t = r.get("Type", "")
        if t == "AWS::IAM::ManagedPolicy":
            return self._arn(name, "Arn")
        if t in ("AWS::SNS::Topic", "AWS::SecretsManager::Secret", "AWS::StepFunctions::StateMachine"):
            return self._arn(name, "Arn")
        if t == "AWS::SQS::Queue":
            return f"https://sqs.{self.pseudo['AWS::Region']}.amazonaws.com/{self.pseudo['AWS::AccountId']}/{self.physical(name)}"
        if t == "AWS::KMS::Key":
            return f"${{{name}.KeyId}}"
        return self.physical(name)

    def _arn(self, logical: str, attr: str) -> Any:
        r = self.resources.get(logical)
        if r is None:
            self.notes.append(f"{self.label}: Fn::GetAtt {logical}.{attr} names nothing in the template.")
            return f"${{{logical}.{attr}}}"
        t, a, p, n = (
            r.get("Type", ""),
            self.pseudo["AWS::AccountId"],
            self.pseudo["AWS::Partition"],
            self.physical(logical),
        )
        path = "/"
        props = r.get("Properties") or {}
        if "Path" in props and isinstance(self.value(props["Path"]), str):
            path = self.value(props["Path"])
        if attr == "Arn":
            if t == "AWS::IAM::Role":
                return f"arn:{p}:iam::{a}:role{path}{n}"
            if t == "AWS::IAM::User":
                return f"arn:{p}:iam::{a}:user{path}{n}"
            if t == "AWS::IAM::Group":
                return f"arn:{p}:iam::{a}:group{path}{n}"
            if t == "AWS::IAM::ManagedPolicy":
                return f"arn:{p}:iam::{a}:policy{path}{n}"
            if t == "AWS::IAM::InstanceProfile":
                return f"arn:{p}:iam::{a}:instance-profile{path}{n}"
            if t == "AWS::KMS::Key":
                return f"arn:{p}:kms:{self.pseudo['AWS::Region']}:{a}:key/${{{logical}.KeyId}}"
            if t in ARNS:
                return ARNS[t][1].format(partition=p, region=self.pseudo["AWS::Region"], account=a, name=n)
        if attr == "RoleId" and t == "AWS::IAM::Role":
            return f"${{{logical}.RoleId}}"
        self.notes.append(
            f"{self.label}: Fn::GetAtt {logical}.{attr} is not known before deployment; shown as ${{{logical}.{attr}}}."
        )
        return f"${{{logical}.{attr}}}"

    # -- conditions
    def condition(self, name: Any) -> bool:
        if not isinstance(name, str):
            return True
        if name not in self._conds:
            conds = self.tpl.get("Conditions") or {}
            if name not in conds:
                self.notes.append(f"{self.label}: condition {name} is not defined; taken as true.")
                self._conds[name] = True
            else:
                self._conds[name] = True  # a condition that refers to itself
                self._conds[name] = self._truth(conds[name])
        return self._conds[name]

    def _truth(self, c: Any) -> bool:
        if isinstance(c, bool):
            return c
        if isinstance(c, dict) and len(c) == 1:
            ((k, v),) = c.items()
            args = v if isinstance(v, list) else [v]
            if k == "Fn::Equals" and len(args) == 2:
                return str(self.value(args[0])) == str(self.value(args[1]))
            if k == "Fn::Not" and args:
                return not self._truth(args[0])
            if k == "Fn::And":
                return all(self._truth(x) for x in args)
            if k == "Fn::Or":
                return any(self._truth(x) for x in args)
            if k == "Condition":
                return self.condition(v)
        self.notes.append(f"{self.label}: a condition could not be evaluated; taken as true.")
        return True

    # -- values
    def value(self, v: Any) -> Any:
        self._depth += 1
        try:
            if self._depth > 60:
                raise TemplateError(f"{self.label}: intrinsic functions nested too deeply")
            return self._value(v)
        finally:
            self._depth -= 1

    def _value(self, v: Any) -> Any:
        if isinstance(v, list):
            out = [self.value(x) for x in v]
            return [x for x in out if x is not NO_VALUE]
        if not isinstance(v, dict):
            return v
        if len(v) == 1:
            ((k, arg),) = v.items()
            if k == "Ref":
                return self._ref(arg)
            if k == "Fn::GetAtt":
                parts = arg.split(".", 1) if isinstance(arg, str) else arg
                if isinstance(parts, list) and len(parts) == 2:
                    return self._arn(str(self.value(parts[0])), str(self.value(parts[1])))
                return "${GetAtt}"
            if k == "Fn::Sub":
                return self._sub(arg)
            if k == "Fn::Join" and isinstance(arg, list) and len(arg) == 2:
                parts = self.value(arg[1])
                return str(self.value(arg[0])).join(str(x) for x in (parts if isinstance(parts, list) else [parts]))
            if k == "Fn::Select" and isinstance(arg, list) and len(arg) == 2:
                lst, i = self.value(arg[1]), self.value(arg[0])
                try:
                    return lst[int(i)]
                except (TypeError, ValueError, IndexError):
                    return "${Select}"
            if k == "Fn::Split" and isinstance(arg, list) and len(arg) == 2:
                s = self.value(arg[1])
                return s.split(str(self.value(arg[0]))) if isinstance(s, str) else ["${Split}"]
            if k == "Fn::FindInMap" and isinstance(arg, list) and len(arg) >= 3:
                m, a, b = (self.value(x) for x in arg[:3])
                try:
                    return self.value(self.tpl["Mappings"][m][a][b])
                except (KeyError, TypeError):
                    if len(arg) == 4 and isinstance(arg[3], dict) and "DefaultValue" in arg[3]:
                        return self.value(arg[3]["DefaultValue"])
                    self.notes.append(
                        f"{self.label}: Fn::FindInMap {m}.{a}.{b} is not in the Mappings; shown as a placeholder."
                    )
                    return f"${{Map:{m}.{a}.{b}}}"
            if k == "Fn::If" and isinstance(arg, list) and len(arg) == 3:
                return self.value(arg[1] if self.condition(arg[0]) else arg[2])
            if k == "Fn::ImportValue":
                name = self.value(arg)
                self.notes.append(
                    f"{self.label}: Fn::ImportValue {name} comes from another stack; shown as ${{Import:{name}}}."
                )
                return f"${{Import:{name}}}"
            if k == "Fn::GetAZs":
                return [f"{self.pseudo['AWS::Region']}a", f"{self.pseudo['AWS::Region']}b"]
            if k == "Fn::Base64":
                return self.value(arg)
            if k == "Fn::ToJsonString":
                return json.dumps(self.value(arg))
            if k.startswith("Fn::") or k == "Condition":
                self.notes.append(f"{self.label}: {k} is not evaluated; shown as a placeholder.")
                return f"${{{k}}}"
        resolved = {k: self.value(x) for k, x in v.items()}
        return {k: x for k, x in resolved.items() if x is not NO_VALUE}

    def _sub(self, arg: Any) -> Any:
        if isinstance(arg, list) and len(arg) == 2 and isinstance(arg[0], str):
            text, local = (
                arg[0],
                {k: self.value(x) for k, x in (arg[1] or {}).items()} if isinstance(arg[1], dict) else {},
            )
        elif isinstance(arg, str):
            text, local = arg, {}
        else:
            return "${Sub}"

        def rep(m: re.Match[str]) -> str:
            name = m.group(1)
            if name.startswith("!"):
                return "${" + name[1:] + "}"  # ${!Literal}
            if name in local:
                return str(local[name])
            if "." in name and name.split(".", 1)[0] in self.resources:
                a, b = name.split(".", 1)
                return str(self._arn(a, b))
            v = self._ref(name)
            return "" if v is NO_VALUE else ",".join(v) if isinstance(v, list) else str(v)

        return re.sub(r"\$\{([^}]+)\}", rep, text)

    def live(self) -> dict[str, dict[str, Any]]:
        """Resources that exist for this stack (their Condition is true), with resolved properties."""
        out: dict[str, dict[str, Any]] = {}
        for logical, r in self.resources.items():
            if "Condition" in r and not self.condition(r["Condition"]):
                continue
            props = self.value(r.get("Properties") or {})
            out[logical] = {"Type": r.get("Type", ""), "Properties": props if isinstance(props, dict) else {}}
        return out


def _doc(v: Any) -> str | None:
    if v is None:
        return None
    return v if isinstance(v, str) else json.dumps(v, sort_keys=True)


def _list(v: Any) -> list[Any]:
    return v if isinstance(v, list) else [] if v is None else [v]


def _names(v: Any) -> list[str]:
    """Role, user or group names: a name, or the last part of an ARN."""
    out = []
    for x in _list(v):
        if isinstance(x, str) and x:
            out.append(x.rsplit("/", 1)[-1] if x.startswith("arn:") else x)
    return out


def _plan_resources(st: _Stack) -> dict[str, tuple[str, dict[str, Any]]]:
    """address -> (Terraform type, after values) for every IAM-relevant resource of the stack."""
    out: dict[str, tuple[str, dict[str, Any]]] = {}
    for logical, r in st.live().items():
        t, p = r["Type"], r["Properties"]
        name = st.physical(logical)
        if t == "AWS::IAM::Role":
            inline = [
                {"name": x.get("PolicyName"), "policy": _doc(x.get("PolicyDocument"))}
                for x in _list(p.get("Policies"))
                if isinstance(x, dict)
            ]
            out[logical] = (
                "aws_iam_role",
                {
                    "name": name,
                    "path": p.get("Path") or "/",
                    "assume_role_policy": _doc(p.get("AssumeRolePolicyDocument")),
                    "inline_policy": inline,
                    "managed_policy_arns": [x for x in _list(p.get("ManagedPolicyArns")) if isinstance(x, str)],
                    "tags": {t2.get("Key"): t2.get("Value") for t2 in _list(p.get("Tags")) if isinstance(t2, dict)},
                },
            )
            if p.get("PermissionsBoundary"):
                st.notes.append(
                    f"{st.label}: {logical} has a permissions boundary; the review of its policies does not apply it."
                )
        elif t in ("AWS::IAM::User", "AWS::IAM::Group"):
            kind = "user" if t == "AWS::IAM::User" else "group"
            out[logical] = (f"aws_iam_{kind}", {"name": name, "path": p.get("Path") or "/"})
            for x in _list(p.get("Policies")):
                if isinstance(x, dict):
                    out[f"{logical}.Policies.{x.get('PolicyName')}"] = (
                        f"aws_iam_{kind}_policy",
                        {kind: name, "name": x.get("PolicyName"), "policy": _doc(x.get("PolicyDocument"))},
                    )
            for arn in _list(p.get("ManagedPolicyArns")):
                if isinstance(arn, str):
                    out[f"{logical}.ManagedPolicyArns.{arn.rsplit('/', 1)[-1]}"] = (
                        f"aws_iam_{kind}_policy_attachment",
                        {kind: name, "policy_arn": arn},
                    )
            if kind == "user" and p.get("Groups"):
                out[f"{logical}.Groups"] = (
                    "aws_iam_user_group_membership",
                    {"user": name, "groups": _names(p.get("Groups"))},
                )
        elif t == "AWS::IAM::ManagedPolicy":
            arn = st._arn(logical, "Arn")
            out[logical] = (
                "aws_iam_policy",
                {"name": name, "path": p.get("Path") or "/", "policy": _doc(p.get("PolicyDocument")), "arn": arn},
            )
            for key, kind in (("Roles", "role"), ("Users", "user"), ("Groups", "group")):
                for owner in _names(p.get(key)):
                    out[f"{logical}.{key}.{owner}"] = (
                        f"aws_iam_{kind}_policy_attachment",
                        {kind: owner, "policy_arn": arn},
                    )
        elif t == "AWS::IAM::Policy":
            for key, kind in (("Roles", "role"), ("Users", "user"), ("Groups", "group")):
                for owner in _names(p.get(key)):
                    out[f"{logical}.{key}.{owner}"] = (
                        f"aws_iam_{kind}_policy",
                        {kind: owner, "name": p.get("PolicyName"), "policy": _doc(p.get("PolicyDocument"))},
                    )
        elif t in ("AWS::IAM::RolePolicy", "AWS::IAM::UserPolicy", "AWS::IAM::GroupPolicy"):
            kind = t.split("::")[2][:-6].lower()
            owners = _names(p.get(f"{kind.capitalize()}Name"))
            if owners:
                out[logical] = (
                    f"aws_iam_{kind}_policy",
                    {kind: owners[0], "name": p.get("PolicyName"), "policy": _doc(p.get("PolicyDocument"))},
                )
        elif t == "AWS::IAM::UserToGroupAddition":
            group = _names(p.get("GroupName"))
            for user in _names(p.get("Users")):
                if group:
                    out[f"{logical}.{user}"] = ("aws_iam_user_group_membership", {"user": user, "groups": group})
        elif t == "AWS::S3::BucketPolicy":
            out[logical] = (
                "aws_s3_bucket_policy",
                {"bucket": p.get("Bucket"), "policy": _doc(p.get("PolicyDocument"))},
            )
        elif t == "AWS::KMS::Key":
            out[logical] = ("aws_kms_key", {"name": logical, "policy": _doc(p.get("KeyPolicy"))})
    return out


def _read(text: str, label: str) -> Any:
    try:
        return loads(text)
    except YamlError as e:
        raise TemplateError(f"{label}: {e}") from None


def to_plan(
    after_text: str,
    before_text: str | None = None,
    *,
    params: dict[str, str] | None = None,
    account: str = "111122223333",
    region: str = "us-east-1",
    stack: str = "stack",
) -> tuple[dict[str, Any], list[str]]:
    """The template (and the one it replaces) as a Terraform-style plan, and the notes on what was resolved."""
    params = params or {}
    after = _Stack(_read(after_text, "template"), "template", params, account, region, stack)
    new = _plan_resources(after)
    notes = after.notes
    old: dict[str, tuple[str, dict[str, Any]]] = {}
    if before_text is not None:
        before = _Stack(_read(before_text, "current template"), "current template", params, account, region, stack)
        old = _plan_resources(before)
        notes += [n for n in before.notes if n not in notes]
    changes = []
    for addr in sorted(set(old) | set(new)):
        b, a = old.get(addr), new.get(addr)
        if b and a and b[0] != a[0]:
            changes.append(
                {"address": addr, "type": b[0], "change": {"actions": ["delete"], "before": b[1], "after": None}}
            )
            changes.append(
                {"address": addr, "type": a[0], "change": {"actions": ["create"], "before": None, "after": a[1]}}
            )
            continue
        if b and a and b[1] == a[1]:
            continue
        actions = ["create"] if not b else ["delete"] if not a else ["update"]
        name_changed = b and a and b[1].get("name") != a[1].get("name")
        if name_changed:
            actions = ["delete", "create"]  # CloudFormation replaces a resource whose name changes
        typ = (a or b)[0]  # type: ignore[index]
        changes.append(
            {
                "address": addr,
                "type": typ,
                "change": {"actions": actions, "before": b[1] if b else None, "after": a[1] if a else None},
            }
        )
    return {"format_version": "1.2", "resource_changes": changes, "source": "cloudformation"}, list(
        dict.fromkeys(notes)
    )


def review(
    after_text: str,
    catalog: Catalog,
    before_text: str | None = None,
    export: dict[str, Any] | None = None,
    *,
    params: dict[str, str] | None = None,
    stack: str = "stack",
    region: str = "us-east-1",
) -> dict[str, Any]:
    account = "111122223333"
    if export is not None:
        for lst in ("RoleDetailList", "UserDetailList", "GroupDetailList"):
            for e in export.get(lst) or [] if isinstance(export, dict) else []:
                parts = str(e.get("Arn", "") if isinstance(e, dict) else "").split(":")
                if len(parts) > 4 and parts[4].isdigit():
                    account = parts[4]
                    break
            if account != "111122223333":
                break
    plan, notes = to_plan(after_text, before_text, params=params, account=account, region=region, stack=stack)
    try:
        r = plan_review(plan, catalog, export=export)
    except TerraformError as e:
        raise TemplateError(str(e)) from None
    r["notes"] = notes + r["notes"]
    r["source"] = "cloudformation"
    return r
