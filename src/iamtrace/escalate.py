"""Privilege escalation and blast radius.

Answers "if this principal is compromised, what can an attacker do?" in three parts:

1. Techniques. For each principal, which known privilege-escalation techniques its policies
   allow. The technique list is pathfinding.cloud's catalog (src/iamtrace/data/escalation_paths.json,
   see NOTICE); every finding cites the pathfinding.cloud page and the research that first
   documented it.
2. Paths. Techniques that hand the attacker another principal (assume a role, pass a role to a
   compute service, create credentials for a user) become edges in a graph. A breadth-first search
   finds the shortest chain from the starting principal to any admin-equivalent principal.
3. Blast radius. With a catalog, every action each reachable principal is allowed on "*",
   counted by access level.

A principal is admin-equivalent when it is allowed Action "*" on Resource "*", or when it has a
self-escalation technique (it can grant itself anything).

Every permission check goes through the evaluation engine, so explicit denies, boundaries,
SCPs and role trust policies are respected.

Input is the output of `aws iam get-account-authorization-details` (the usual way to export an
account's IAM configuration), or a single policy file evaluated as one hypothetical role.

Confidence. "confirmed" means every permission and the target's trust policy were checked.
"possible" means the target could not be checked: the technique abuses existing resources
(an existing Lambda function, EC2 instance, ...) that the IAM export does not list, the target is
only known as a resource pattern, or iam-trace does not know which service principal must trust
the passed role. Only confirmed edges form paths.

A resource inventory (iamtrace.inventory) lists the existing resources and their roles. With one,
existing-resource techniques are checked against each resource and become confirmed, or are
ruled out when the kind was collected and nothing matches.

Conditions. Each check carries the caller's tags (aws:PrincipalTag) and, for a user or role target,
its tags (aws:ResourceTag, iam:ResourceTag) from the export. A check that fails is retried with
the values its conditions name (iamtrace.gates): values the attacker chooses (region, request tags,
ExternalId) make it open; MFA, a network location or a time window make it *gated*. Gated
techniques, edges and paths carry "requires", so an open path (anyone with the credentials) can be
told from one that needs, say, MFA. `analyze(..., conditions=False)` turns the retry off.
"""

from __future__ import annotations

import json
import urllib.parse
from collections import deque
from dataclasses import dataclass, field, replace
from functools import cache
from importlib import resources
from typing import Any

from iamtrace.arn import resource_matches
from iamtrace.catalog import ACCESS_LEVELS, Catalog
from iamtrace.context import Context
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.gates import Gate, condition_values, describe, find_gates, summary
from iamtrace.inventory import AGENTCORE_PREFIX, TECHNIQUE_KIND, Inventory
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy, PolicyError, PolicyType
from iamtrace.output import sarif_log
from iamtrace.principals import GrantKind, Principal, match_principal_element

# Which kind of IAM resource each targeted permission acts on.
PERMISSION_TARGET: dict[str, str] = {
    "iam:createpolicyversion": "policy",
    "iam:setdefaultpolicyversion": "policy",
    "iam:createaccesskey": "user",
    "iam:deleteaccesskey": "user",
    "iam:createloginprofile": "user",
    "iam:updateloginprofile": "user",
    "iam:putuserpolicy": "user",
    "iam:attachuserpolicy": "user",
    "iam:putrolepolicy": "role",
    "iam:attachrolepolicy": "role",
    "iam:updateassumerolepolicy": "role",
    "iam:passrole": "role",
    "sts:assumerole": "role",
    "iam:putgrouppolicy": "group",
    "iam:attachgrouppolicy": "group",
    "iam:addusertogroup": "group",
}

# The service principal that must trust a role passed by a "new-passrole" technique, keyed by
# the technique ID prefix. Best effort: a prefix that is missing here means the trust policy is
# not checked and the finding is "possible".
SERVICE_PRINCIPALS: dict[str, str] = {
    "apprunner": "tasks.apprunner.amazonaws.com",
    "batch": "ecs-tasks.amazonaws.com",
    "bedrock": "bedrock-agentcore.amazonaws.com",
    "braket": "braket.amazonaws.com",
    "cloudformation": "cloudformation.amazonaws.com",
    "codebuild": "codebuild.amazonaws.com",
    "codedeploy": "codedeploy.amazonaws.com",
    "datapipeline": "datapipeline.amazonaws.com",
    "ec2": "ec2.amazonaws.com",
    "ecs": "ecs-tasks.amazonaws.com",
    "emr": "elasticmapreduce.amazonaws.com",
    "emrserverless": "emr-serverless.amazonaws.com",
    "gamelift": "gamelift.amazonaws.com",
    "glue": "glue.amazonaws.com",
    "imagebuilder": "ec2.amazonaws.com",
    "kinesisanalytics": "kinesisanalytics.amazonaws.com",
    "lambda": "lambda.amazonaws.com",
    "omics": "omics.amazonaws.com",
    "sagemaker": "sagemaker.amazonaws.com",
    "scheduler": "scheduler.amazonaws.com",
    "ssm": "ssm.amazonaws.com",
    "stepfunctions": "states.amazonaws.com",
    "cognitoidentity": "cognito-identity.amazonaws.com",
}

# Techniques whose passed role may instead trust another service, as pathfinding.cloud's
# prerequisites describe it. Either trust makes the finding confirmed.
ALSO_TRUSTED: dict[str, tuple[str, ...]] = {
    "batch-001": ("batch.amazonaws.com",),
    "gamelift-001": ("ec2.amazonaws.com",),
}

# Principals that assume a role through web identity federation (sts:AssumeRoleWithWebIdentity
# from a "Federated" principal) rather than as a service.
FEDERATED_SERVICES = frozenset({"cognito-identity.amazonaws.com"})

MODIFY_PERMISSIONS = frozenset(
    {
        "iam:attachrolepolicy",
        "iam:putrolepolicy",
        "iam:createpolicyversion",
        "iam:attachuserpolicy",
        "iam:putuserpolicy",
    }
)

FULL_ADMIN = "allowed every action on every resource"

_NO_CONTEXT = Context()

ADMIN_PROBE = "iamtraceprobe:AnyAction"  # only Action "*" (or a NotAction that spares it) matches


@cache
def technique_catalog() -> list[dict[str, Any]]:
    data = json.loads(resources.files("iamtrace").joinpath("data/escalation_paths.json").read_text())
    paths: list[dict[str, Any]] = data["paths"]
    return paths


# --- environment ------------------------------------------------------------------------


@dataclass
class Node:
    arn: str
    kind: str  # "user" | "role"
    policies: list[Policy]
    boundary: Policy | None = None
    trust: Policy | None = None
    groups: list[str] = field(default_factory=list)  # group ARNs
    attached: list[str] = field(default_factory=list)  # managed policy ARNs, incl. via groups
    tags: dict[str, str] = field(default_factory=dict)

    @property
    def account(self) -> str:
        return self.arn.split(":")[4]

    def caller(self) -> Principal:
        return _caller(self.arn)


@cache
def _caller(arn: str) -> Principal:
    return Principal.from_arn(arn)


def _tags(entity: dict[str, Any]) -> dict[str, str]:
    return {
        str(t["Key"]): str(t.get("Value", "")) for t in entity.get("Tags") or [] if isinstance(t, dict) and "Key" in t
    }


def _document(value: Any, where: str) -> Any:
    if isinstance(value, str):
        # The raw API returns URL-encoded JSON; the AWS CLI decodes it.
        try:
            return json.loads(urllib.parse.unquote(value))
        except json.JSONDecodeError as e:
            raise PolicyError(f"{where}: policy document is not JSON") from e
    return value


class Environment:
    def __init__(
        self,
        nodes: dict[str, Node],
        groups: dict[str, str],
        warnings: list[str],
        raw: dict[str, Any] | None = None,
        inventory: bool = True,
    ) -> None:
        self.nodes = nodes
        self.groups = groups  # group ARN -> name
        self.warnings = warnings
        self.raw = raw or {}
        self.inventory = inventory  # False for a single policy with no account export
        self.resources: Inventory | None = None  # existing resources and their roles, if given
        self.group_policies: dict[str, list[Policy]] = {}  # group ARN -> its own policies

    @classmethod
    def from_auth_details(cls, data: dict[str, Any]) -> Environment:
        """Build from `aws iam get-account-authorization-details` output. Raises PolicyError, with
        a message naming the problem, for anything that is not a well-formed export."""
        if not isinstance(data, dict) or not any(
            k in data for k in ("UserDetailList", "RoleDetailList", "GroupDetailList", "Policies")
        ):
            raise PolicyError("not an account export: expected the output of aws iam get-account-authorization-details")
        try:
            return cls._from_auth_details(data)
        except (KeyError, TypeError, AttributeError) as e:
            raise PolicyError(f"malformed account export: missing or invalid field {e}") from e

    @classmethod
    def _from_auth_details(cls, data: dict[str, Any]) -> Environment:
        warnings: list[str] = []
        managed: dict[str, Policy] = {}
        for p in data.get("Policies", []):
            versions = p.get("PolicyVersionList") or []
            default = next((v for v in versions if v.get("IsDefaultVersion")), None)
            if default is None:
                warnings.append(f"{p['Arn']}: no default version in the export; ignored")
                continue
            managed[p["Arn"]] = Policy.parse(
                _document(default["Document"], p["Arn"]), policy_id=p["Arn"], policy_type=PolicyType.IDENTITY
            )

        def attached(entity: dict[str, Any], label: str) -> tuple[list[Policy], list[str]]:
            pols, arns = [], []
            for a in entity.get("AttachedManagedPolicies") or []:
                arns.append(a["PolicyArn"])
                if a["PolicyArn"] in managed:
                    pols.append(managed[a["PolicyArn"]])
                else:
                    warnings.append(f"{label}: managed policy {a['PolicyArn']} is not in the export; ignored")
            return pols, arns

        def inline(entity: dict[str, Any], key: str, label: str) -> list[Policy]:
            return [
                Policy.parse(
                    _document(i["PolicyDocument"], f"{label}/{i['PolicyName']}"),
                    policy_id=f"{label} inline {i['PolicyName']}",
                    policy_type=PolicyType.IDENTITY,
                )
                for i in entity.get(key) or []
            ]

        def boundary(entity: dict[str, Any], label: str) -> Policy | None:
            b = entity.get("PermissionsBoundary")
            if not b:
                return None
            arn = b.get("PermissionsBoundaryArn")
            if arn in managed:
                pol = managed[arn]
                return Policy(pol.id, PolicyType.BOUNDARY, pol.version, pol.statements, pol.warnings)
            warnings.append(f"{label}: permissions boundary {arn} is not in the export; boundary ignored")
            return None

        groups_by_name: dict[str, tuple[str, list[Policy], list[str]]] = {}
        group_arns: dict[str, str] = {}
        for g in data.get("GroupDetailList", []):
            label = g["Arn"]
            pols, arns = attached(g, label)
            groups_by_name[g["GroupName"]] = (g["Arn"], inline(g, "GroupPolicyList", label) + pols, arns)
            group_arns[g["Arn"]] = g["GroupName"]

        nodes: dict[str, Node] = {}
        for u in data.get("UserDetailList", []):
            label = u["Arn"]
            pols, arns = attached(u, label)
            policies = inline(u, "UserPolicyList", label) + pols
            gl = []
            for gname in u.get("GroupList") or []:
                if gname not in groups_by_name:
                    warnings.append(f"{label}: group {gname} is not in the export; ignored")
                    continue
                garn, gpols, garns = groups_by_name[gname]
                gl.append(garn)
                policies += gpols
                arns += garns
            nodes[u["Arn"]] = Node(
                u["Arn"], "user", policies, boundary(u, label), groups=gl, attached=arns, tags=_tags(u)
            )
        for r in data.get("RoleDetailList", []):
            label = r["Arn"]
            pols, arns = attached(r, label)
            trust = Policy.parse(
                _document(r["AssumeRolePolicyDocument"], label),
                policy_id=f"{label} trust policy",
                policy_type=PolicyType.RESOURCE,
            )
            nodes[r["Arn"]] = Node(
                r["Arn"],
                "role",
                inline(r, "RolePolicyList", label) + pols,
                boundary(r, label),
                trust=trust,
                attached=arns,
                tags=_tags(r),
            )
        env = cls(nodes, group_arns, warnings, raw=data)
        env.group_policies = {garn: gpols for garn, gpols, _ in groups_by_name.values()}
        return env

    @classmethod
    def single(cls, policies: list[Policy], principal_arn: str, boundary: Policy | None = None) -> Environment:
        kind = "user" if ":user/" in principal_arn else "role"
        node = Node(principal_arn, kind, policies, boundary)
        return cls({principal_arn: node}, {}, [], inventory=False)


# --- analysis ----------------------------------------------------------------------------


@dataclass
class Edge:
    source: str
    target: str
    technique: str
    name: str
    grants_admin: bool
    gates: frozenset[Gate] = frozenset()


class _Analyzer:
    def __init__(self, env: Environment, scps: list[list[Policy]] | None, conditions: bool = True) -> None:
        self.env = env
        self.scps = scps
        self.conditions = conditions
        self.gated_ok = conditions  # off while looking for an open way first
        self._acc: set[Gate] | None = None  # gates used by the checks of the technique being tested
        self._cache: dict[tuple[str, str, str, str], frozenset[Gate] | None] = {}
        self._sig_cache: dict[tuple[Any, ...], frozenset[Gate] | None] = {}
        self._has_keys: dict[int, tuple[Policy, bool]] = {}
        self._loose_cache: dict[int, tuple[Policy, Policy]] = {}  # keeps the original alive: ids stay unique
        self._may: dict[tuple[str, str], bool] = {}
        self._trust: dict[tuple[str, str], bool] = {}
        self._patterns: dict[str, tuple[str, ...] | None] = {}
        self._admits: dict[tuple[str, str], bool] = {}
        self._by_type: dict[str, list[str]] = {}
        self._ctx_keys: dict[tuple[tuple[str, str], ...], str] = {}
        self._may_on: dict[tuple[str, str, str], bool] = {}
        self._hits: dict[tuple[tuple[str, ...], str], tuple[str, ...]] = {}

    def can(
        self,
        node: Node,
        action: str,
        resource: str,
        *,
        trust: Policy | None = None,
        context: dict[str, Any] | None = None,
    ) -> bool:
        key = (
            node.arn,
            action.lower(),
            resource,
            (self._context_key(context) if context else "") + (trust.id if trust else ""),
        )
        if key not in self._cache and trust is None and not self._identity_may_on(node, action, resource):
            # No resource policy here, so only the identity policies could allow it: none can.
            self._cache[key] = None
        if key not in self._cache:
            # Resources that the same policy patterns match, with the same trust policy and tags,
            # get the same answer: decide once per signature (as _existing does for inventories).
            sig = self._signature(node, action, resource, trust, key[3])
            if sig is not None and sig in self._sig_cache:
                self._cache[key] = self._sig_cache[sig]
            else:
                self._cache[key] = self._decide(node, action, resource, trust, context)
                if sig is not None:
                    self._sig_cache[sig] = self._cache[key]
        gates = self._cache[key]
        if gates is None or (gates and not self.gated_ok):
            return False
        if gates and self._acc is not None:
            self._acc |= gates
        return True

    def _context_key(self, context: dict[str, Any]) -> str:
        """A stable string for a request context (the analysis reuses a handful of them)."""
        flat = tuple(sorted((k, json.dumps(v, sort_keys=True)) for k, v in context.items()))
        key = self._ctx_keys.get(flat)
        if key is None:
            key = self._ctx_keys[flat] = json.dumps(context, sort_keys=True)
        return key

    def _signature(
        self, node: Node, action: str, resource: str, trust: Policy | None, ctx_key: str
    ) -> tuple[Any, ...] | None:
        patterns = self._resource_patterns(node)
        if patterns is None:
            return None
        parts = resource.split(":", 5)
        account = parts[4] if len(parts) > 4 and parts[0] == "arn" and parts[4] else node.account
        target = self.env.nodes.get(resource)
        tags = tuple(sorted(target.tags.items())) if target is not None else ()
        hkey = (patterns, resource)
        hit = self._hits.get(hkey)
        if hit is None:
            hit = tuple(x for x in patterns if resource_matches(x, resource, _NO_CONTEXT, False))
            self._hits[hkey] = hit
        # The trust policy is part of the answer, and so is the target itself when the policies name
        # it by exact ARN (hit then differs) or the trust policy is its own (keyed by id).
        return (
            node.arn,
            action.lower(),
            account,
            hit,
            id(trust) if trust else None,
            tags,
            ctx_key,
            resource == node.arn,
        )

    def _decide(
        self, node: Node, action: str, resource: str, trust: Policy | None, context: dict[str, Any] | None
    ) -> frozenset[Gate] | None:
        """frozenset() if allowed as is, the gates it needs if only a gated context allows it, else None."""
        # The resource's own account when its ARN has one (S3 ARNs do not), else the caller's.
        parts = resource.split(":", 5)
        account = parts[4] if len(parts) > 4 and parts[0] == "arn" and parts[4] else node.account
        ctx: dict[str, Any] = {f"aws:PrincipalTag/{k}": v for k, v in node.tags.items()}
        target = self.env.nodes.get(resource)
        if target is not None:
            for k, v in target.tags.items():
                ctx[f"aws:ResourceTag/{k}"] = v
                ctx[f"iam:ResourceTag/{k}"] = v
        ctx.update(context or {})
        req = Request(node.caller(), action, resource, resource_account=account, context=ctx)
        ps = PolicySet(
            identity=node.policies, boundary=node.boundary, scps=self.scps, resource=[trust] if trust else []
        )
        if evaluate(req, ps).allowed:
            return frozenset()
        if not self.conditions:
            return None
        pols = [*node.policies, *([node.boundary] if node.boundary else []), *([trust] if trust else [])]
        pols += [p for level in self.scps or [] for p in level]
        if not self._searchable(pols):
            return None  # no condition the attacker could satisfy: nothing to search
        # Upper bound: with every Deny gone and every Allow unconditional, is it allowed? If not,
        # no context can allow it, and the search is skipped. Most failed checks end here.
        loose = PolicySet(
            identity=[self._loose(p) for p in node.policies],
            boundary=self._loose(node.boundary) if node.boundary else None,
            scps=[[self._loose(p) for p in level] for level in self.scps] if self.scps else None,
            resource=[self._loose(trust)] if trust else [],
        )
        if not evaluate(req, loose).allowed:
            return None
        return find_gates(lambda c: evaluate(replace(req, context=c), ps).allowed, ctx, pols)

    def _searchable(self, pols: list[Policy]) -> bool:
        """Does any of these policies have a condition key the gate search can vary?"""
        out = False
        for pol in pols:
            key = id(pol)
            if key not in self._has_keys:
                self._has_keys[key] = (pol, bool(condition_values([pol])))
            out = out or self._has_keys[key][1]
        return out

    def _loose(self, pol: Policy) -> Policy:
        """The policy with its Deny statements removed and its Allow statements unconditional."""
        key = id(pol)
        if key not in self._loose_cache:
            sts = tuple(replace(st, condition={}) for st in pol.statements if st.effect == "Allow")
            self._loose_cache[key] = (pol, replace(pol, statements=sts))
        return self._loose_cache[key][1]

    def trust_admits(self, role: Node, node: Node) -> bool:
        """Cheap over-approximation: could the role's trust policy let this node assume it?

        True if an Allow statement's Principal names the caller (its ARN, its role, "*") or uses
        NotPrincipal. If the only match is the caller's account, the caller's own policies must
        also allow sts:AssumeRole, so that is checked too. Conditions are ignored, so a False
        here means the full evaluation would deny as well.
        """
        if role.trust is None:
            return False
        key = (role.arn, node.arn)
        if key not in self._admits:
            caller = node.caller()
            best: GrantKind | None = None
            for st in role.trust.statements:
                if st.effect != "Allow":
                    continue
                if st.not_principal is not None:
                    best = GrantKind.DIRECT
                    break
                if st.principal is None:
                    continue
                grant = match_principal_element(st.principal, caller)
                if grant is not None and (best is None or grant != GrantKind.ACCOUNT):
                    best = grant
            if best == GrantKind.ACCOUNT:
                self._admits[key] = self._identity_may_on(node, "sts:AssumeRole", role.arn)
            else:
                self._admits[key] = best is not None
        return self._admits[key]

    def may_allow(self, node: Node, action: str) -> bool:
        """Cheap over-approximation: can any of the node's Allow statements cover this action?

        If not, no resource and no condition can make the identity policies allow it, so the
        expensive per-target checks are skipped. sts:AssumeRole is the exception: a role's trust
        policy can grant it directly, so it is always checked per target.
        """
        if action.lower() == "sts:assumerole":
            return True
        return self._identity_may(node, action)

    def _identity_may_on(self, node: Node, action: str, resource: str) -> bool:
        """Cheap over-approximation: could one of the node's Allow statements cover this action on
        this resource? Conditions are ignored, and a pattern with a policy variable counts as
        matching, so False means the identity policies cannot allow it."""
        if node.kind == "root":
            return True
        key = (node.arn, action.lower(), resource)
        hit = self._may_on.get(key)
        if hit is None:
            hit = False
            for pol in node.policies:
                for st in pol.statements:
                    if st.effect != "Allow":
                        continue
                    if st.actions is not None:
                        if not any_action_matches(st.actions, action):
                            continue
                    elif any_action_matches(st.not_actions or (), action):
                        continue
                    if st.resources is not None:
                        ok = any("${" in x or resource_matches(x, resource, _NO_CONTEXT, False) for x in st.resources)
                    else:
                        ok = not any(
                            "${" not in x and resource_matches(x, resource, _NO_CONTEXT, False)
                            for x in st.not_resources or ()
                        )
                    if ok:
                        hit = True
                        break
                if hit:
                    break
            self._may_on[key] = hit
        return hit

    def _identity_may(self, node: Node, action: str) -> bool:
        """Can any of the node's Allow statements cover this action (ignoring resources and
        conditions)?"""
        key = (node.arn, action.lower())
        if key not in self._may:
            self._may[key] = (
                any(
                    st.effect == "Allow"
                    and (
                        any_action_matches(st.actions, action)
                        if st.actions is not None
                        else not any_action_matches(st.not_actions or (), action)
                    )
                    for pol in node.policies
                    for st in pol.statements
                )
                or node.kind == "root"
            )
        return self._may[key]

    def candidates(self, node: Node, action: str) -> list[str]:
        """Resources to probe for an action we have no inventory for: "*" plus every resource
        pattern of the node's own Allow statements that cover the action."""
        out = {"*"}
        for pol in node.policies:
            for st in pol.statements:
                if st.effect == "Allow" and st.actions and any_action_matches(st.actions, action) and st.resources:
                    out.update(st.resources)
        return sorted(out)

    def any_allowed(self, node: Node, action: str, context: dict[str, Any] | None = None) -> bool:
        cands = self.candidates(node, action)
        saved = self.gated_ok
        self.gated_ok = False  # an open way, if there is one, before a gated one
        try:
            if any(self.can(node, action, r, context=context) for r in cands):
                return True
        finally:
            self.gated_ok = saved
        return saved and any(self.can(node, action, r, context=context) for r in cands)

    def is_admin(self, node: Node) -> bool:
        return self.can(node, ADMIN_PROBE, "*")

    # -- targets ---------------------------------------------------------------------

    def targets(self, node: Node, ttype: str, *, others: bool) -> list[str]:
        if ttype not in self._by_type:
            env = self.env
            if ttype in ("user", "role"):
                arns = [a for a, n in env.nodes.items() if n.kind == ttype]
            elif ttype == "group":
                arns = list(env.groups)
            else:
                arns = []
            self._by_type[ttype] = sorted(arns)
        every = self._by_type[ttype]
        return [a for a in every if a != node.arn] if others and ttype in ("user", "role") else list(every)

    def trusted_by_service(self, role: Node, service: str) -> bool:
        if role.trust is None:
            return False
        key = (role.arn, service)
        if key not in self._trust:
            if service in FEDERATED_SERVICES:
                req = Request(
                    Principal.web_identity(service),
                    "sts:AssumeRoleWithWebIdentity",
                    role.arn,
                    resource_account=role.account,
                )
            else:
                req = Request(Principal.service(service), "sts:AssumeRole", role.arn, resource_account=role.account)
            self._trust[key] = evaluate(req, PolicySet(resource=[role.trust])).allowed
        return self._trust[key]

    def trusted_for(self, role: Node, tid: str, service: str | None) -> bool:
        """Does the role trust the service a technique passes it to (or an alternative)?"""
        options = ((service,) if service else ()) + ALSO_TRUSTED.get(tid, ())
        return any(self.trusted_by_service(role, x) for x in options)

    # -- techniques --------------------------------------------------------------------

    def techniques(self, node: Node) -> tuple[list[dict[str, Any]], list[Edge]]:
        found: list[dict[str, Any]] = []
        edges: list[Edge] = []
        for t in technique_catalog():
            shared: set[Gate] = set()
            self._acc = shared
            self._target_gates: dict[str, set[Gate]] = {}
            try:
                result = self._check(node, t)
            finally:
                self._acc = None
            if result is None:
                continue
            # (targets, confidence, grants_admin, edge_targets[, via]): via names the existing
            # resources an inventory-backed finding goes through.
            targets, confidence, grants_admin, edge_targets = result[:4]
            via: list[str] = list(result[4]) if len(result) > 4 else []
            per_target = {x: frozenset(shared | g) for x, g in self._target_gates.items() if x in targets}
            every = set(shared).union(*per_target.values()) if per_target else set(shared)
            # A technique is gated only if every target needs a gate; then it lists what they need.
            open_somewhere = not shared and (not per_target or any(not g for g in per_target.values()))
            requires = [] if open_somewhere else describe(every)
            found.append(
                {
                    "id": t["id"],
                    "name": t["name"],
                    "category": t["category"],
                    "permissions": t["permissions"],
                    "targets": targets,
                    "confidence": confidence,
                    "grants_admin": grants_admin,
                    **({"via": via} if via else {}),
                    **({"requires": requires} if requires else {}),
                    **(
                        {"gated_targets": {x: describe(g) for x, g in per_target.items() if g}}
                        if any(per_target.values()) and open_somewhere
                        else {}
                    ),
                    "source": {
                        "pathfinding": t["pathfinding_url"],
                        "first_documented": t["first_documented"].get("link"),
                        "author": ", ".join(
                            x
                            for x in (t["first_documented"].get("author"), t["first_documented"].get("organization"))
                            if x
                        ),
                    },
                }
            )
            for target in edge_targets:
                gates = frozenset(shared | self._target_gates.get(target, set()))
                edges.append(Edge(node.arn, target, t["id"], t["name"], grants_admin, gates))
        return found, edges

    def _per_target(self, target: str, check: Any) -> bool:
        """Run a check for one target, keeping the gates it uses apart from the technique's."""
        outer = self._acc
        mine: set[Gate] = set()
        self._acc = mine
        try:
            ok = bool(check())
        finally:
            self._acc = outer
        if ok:
            self._record_target(target, mine)
        return ok

    def _record_target(self, target: str, gates: set[Gate]) -> None:
        """Note what reaching a target needs. Several ways to the same target (two resources that
        run as one role): an open one wins over a gated one."""
        prev = self._target_gates.get(target)
        if prev is None or (prev and not gates):
            self._target_gates[target] = gates

    def _perm_ok(
        self, node: Node, perm: str, target: Node | str | None, extra_ctx: dict[str, Any] | None = None
    ) -> bool:
        ptype = PERMISSION_TARGET.get(perm.lower())
        tnode = target if isinstance(target, Node) else None
        if ptype in ("user", "role") and tnode is not None:
            assume = perm.lower() == "sts:assumerole"
            if assume and not self.trust_admits(tnode, node):
                return False
            trust = tnode.trust if assume else None
            return self.can(node, perm, tnode.arn, trust=trust, context=extra_ctx)
        if ptype == "policy" and tnode is not None:
            customer = [a for a in tnode.attached if ":iam::aws:policy/" not in a]
            return any(self.can(node, perm, a) for a in customer)
        if ptype == "group" and isinstance(target, str) and target.startswith("arn:"):
            return self.can(node, perm, target)
        return self.any_allowed(node, perm, extra_ctx)

    def _check(self, node: Node, t: dict[str, Any]) -> tuple[list[str], str, bool, list[str]] | None:
        perms: list[str] = t["permissions"]
        cat = t["category"]
        tid: str = t["id"]
        env = self.env

        if not all(self.may_allow(node, p) for p in perms):
            return None
        if cat == "self-escalation":
            return self._self_escalation(node, t)

        if cat == "principal-access":
            ttypes = [PERMISSION_TARGET.get(p.lower()) for p in perms]
            ttype = next((x for x in ttypes if x in ("user", "role")), "role")
            # Combinations that both change the target's permissions and give access to it.
            grants_admin = len(perms) > 1 and any(p.lower() in MODIFY_PERMISSIONS for p in perms)
            if not env.inventory:
                if all(self.any_allowed(node, p) for p in perms):
                    return ([f"any {ttype} the policy's resources allow"], "possible", grants_admin, [])
                return None
            hits = []
            for arn in self.targets(node, ttype, others=True):
                tnode = env.nodes[arn]
                if self._per_target(arn, lambda tnode=tnode: all(self._perm_ok(node, p, tnode) for p in perms)):
                    hits.append(arn)
            return (hits, "confirmed", grants_admin, hits) if hits else None

        service = tid.rsplit("-", 1)[0]
        svc_principal = SERVICE_PRINCIPALS.get(service)
        if cat == "new-passrole" and not any(p.lower() == "iam:passrole" for p in perms):
            # A role already attached to an existing resource (a CloudFormation change set on a
            # stack with a service role): no role is passed, so check it as an existing resource.
            cat = "existing-passrole"
        if cat == "new-passrole":
            others = [p for p in perms if p.lower() != "iam:passrole"]
            if not all(self.any_allowed(node, p) for p in others):
                return None
            ctx = {"iam:PassedToService": svc_principal} if svc_principal else {}
            if not env.inventory:
                if self.any_allowed(node, "iam:PassRole", ctx):
                    return (["any role the policy lets it pass"], "possible", False, [])
                return None
            hits = []
            possible: list[str] = []
            unknown_service = svc_principal is None and tid not in ALSO_TRUSTED
            for arn in self.targets(node, "role", others=True):
                tnode = env.nodes[arn]
                # A role the service cannot assume is no finding, so check the (cached) trust first.
                if not unknown_service and not self.trusted_for(tnode, tid, svc_principal):
                    continue
                if not self._per_target(arn, lambda arn=arn: self.can(node, "iam:PassRole", arn, context=ctx)):
                    continue
                (possible if unknown_service else hits).append(arn)
            if hits:
                return (hits, "confirmed", False, hits)
            if possible:
                return (possible, "possible", False, [])
            return None

        if cat == "existing-passrole":
            kind = TECHNIQUE_KIND.get(tid)
            inv = env.resources
            if inv is not None and kind in inv.collected:
                return self._existing(node, perms, inv, kind, AGENTCORE_PREFIX.get(tid))
            if not all(self.any_allowed(node, p) for p in perms):
                return None
            roles = [
                a
                for a in self.targets(node, "role", others=True)
                if self.trusted_for(self.env.nodes[a], tid, svc_principal)
            ]
            label = roles or [f"existing {service} resources and the roles attached to them (not in the IAM export)"]
            return (label, "possible", False, [])
        return None

    def _existing(
        self, node: Node, perms: list[str], inv: Inventory, kind: str, prefix: str | None = None
    ) -> tuple[Any, ...] | None:
        """Check an existing-resource technique against each inventoried resource of its kind
        (only those whose resource part starts with prefix, when given)."""
        roles: set[str] = set()
        via: set[str] = set()
        # signature -> the gates its resources need (None: not allowed), so each role keeps the
        # gates of the resource it is reached through rather than the technique's union.
        decided: dict[tuple[str, ...], frozenset[Gate] | None] = {}
        patterns = self._resource_patterns(node)
        for r in inv.of_kind(kind):
            if r.role is None or r.role == node.arn:
                continue
            if prefix and not r.arn.split(":", 5)[5].startswith(prefix):
                continue
            # Resources that the same Resource/NotResource patterns match, in the same account,
            # get the same decision, so evaluate once per group. Patterns with policy variables
            # depend on the request, so those fall back to one evaluation per resource.
            if patterns is None:
                sig: tuple[str, ...] = (r.arn,)
            else:
                acct = r.arn.split(":")[4]
                sig = (acct, *(x for x in patterns if resource_matches(x, r.arn, _NO_CONTEXT, False)))
            if sig not in decided:
                outer = self._acc
                mine: set[Gate] = set()
                self._acc = mine
                try:
                    ok = all(self.can(node, p, r.arn) for p in perms)
                finally:
                    self._acc = outer
                decided[sig] = frozenset(mine) if ok else None
            gates = decided[sig]
            if gates is not None:
                self._record_target(r.role, set(gates))
                roles.add(r.role)
                via.add(r.arn)
        if not roles:
            return None  # the kind was collected and nothing reachable runs as a role
        edges = sorted(x for x in roles if x in self.env.nodes)
        return (sorted(roles), "confirmed", False, edges, sorted(via))

    def _resource_patterns(self, node: Node) -> tuple[str, ...] | None:
        """Every Resource and NotResource pattern in the policies that decide for this node, or
        None if any of them uses a policy variable."""
        if node.arn not in self._patterns:
            pols = list(node.policies) + ([node.boundary] if node.boundary else [])
            pols += [p for level in self.scps or [] for p in level]
            pats = sorted(
                {x for pol in pols for st in pol.statements for x in (st.resources or ()) + (st.not_resources or ())}
            )
            self._patterns[node.arn] = None if any("${" in x for x in pats) else tuple(pats)
        return self._patterns[node.arn]

    def _self_escalation(self, node: Node, t: dict[str, Any]) -> tuple[list[str], str, bool, list[str]] | None:
        perms = [p.lower() for p in t["permissions"]]
        main = perms[0]
        ttype = PERMISSION_TARGET.get(main)
        env = self.env
        pool: list[str]
        if ttype == "policy":
            pool = [a for a in self._attached(node) if ":iam::aws:policy/" not in a]
            if not env.inventory:
                pool = self.candidates(node, main)
        elif ttype in ("user", "role"):
            pool = [node.arn] if node.kind == ttype else []
        elif ttype == "group":
            if main == "iam:addusertogroup":
                if node.kind != "user":
                    return None
                pool = list(env.groups) if env.inventory else self.candidates(node, main)
                # Joining a group gains its permissions: only a group that makes the user admin
                # counts (with no export, the groups are unknown and any is possible).
                if env.inventory:
                    pool = [g for g in pool if g not in node.groups and self._group_makes_admin(node, g)]
            else:
                pool = node.groups if env.inventory else self.candidates(node, main)
        else:
            pool = []
        # Each target keeps its own gates, so one target that needs MFA does not mark the
        # technique as needing MFA when another target is open.
        targets = [x for x in pool if self._per_target(x, lambda x=x: self.can(node, main, x))]
        if not targets:
            return None
        confidence = "confirmed" if env.inventory else "possible"
        return (sorted(targets), confidence, True, [])

    def _group_makes_admin(self, node: Node, group: str) -> bool:
        """Would the user be allowed everything after joining the group? Checked with the user's
        own policies plus the group's, under the user's boundary and the SCPs."""
        extra = self.env.group_policies.get(group, [])
        if not extra:
            return False
        req = Request(node.caller(), ADMIN_PROBE, "*", resource_account=node.account)
        ps = PolicySet(identity=[*node.policies, *extra], boundary=node.boundary, scps=self.scps)
        return evaluate(req, ps).allowed

    def _attached(self, node: Node) -> list[str]:
        return node.attached


class AnalysisCache:
    """Per-principal results to share between analyze() calls on the same account.

    Pass the same cache to several calls (from everyone, then from one principal) and each
    principal is worked out once. It is used only while the account, the SCPs and the
    conditions setting are the very same objects; otherwise it starts over.
    """

    def __init__(self) -> None:
        self.key: tuple[int, int, bool] | None = None
        self.analyzer: _Analyzer | None = None
        self.visits: dict[str, tuple[list[dict[str, Any]], list[Edge], str | None, frozenset[Gate] | None]] = {}
        self._keep: tuple[Any, ...] = ()  # the keyed objects, so their ids stay theirs

    def analyzer_for(self, env: Environment, scps: list[list[Policy]] | None, conditions: bool) -> _Analyzer:
        key = (id(env), id(scps), conditions)
        if self.key != key or self.analyzer is None:
            self.key, self.analyzer, self.visits, self._keep = key, _Analyzer(env, scps, conditions), {}, (env, scps)
        return self.analyzer


def analyze(
    env: Environment,
    start: str | None = None,
    *,
    catalog: Catalog | None = None,
    scps: list[list[Policy]] | None = None,
    conditions: bool = True,
    cache: AnalysisCache | None = None,
) -> dict[str, Any]:
    a = cache.analyzer_for(env, scps, conditions) if cache else _Analyzer(env, scps, conditions)
    if start is not None and start not in env.nodes:
        raise ValueError(f"{start} is not in the account export")

    techniques: dict[str, list[dict[str, Any]]] = {}
    edges: dict[str, list[Edge]] = {}
    admin: dict[str, str | None] = {}
    admin_gates: dict[str, frozenset[Gate]] = {}

    def visit(arn: str) -> None:
        if arn in techniques:
            return
        if cache and arn in cache.visits:
            techniques[arn], edges[arn], admin[arn], g = cache.visits[arn]
            if g is not None:
                admin_gates[arn] = g
            return
        _visit(arn)
        if cache:
            cache.visits[arn] = (techniques[arn], edges[arn], admin[arn], admin_gates.get(arn))

    def _visit(arn: str) -> None:
        node = env.nodes[arn]
        found, out = a.techniques(node)
        techniques[arn] = found
        edges[arn] = out
        gates: set[Gate] = set()
        a._acc = gates
        try:
            full = a.is_admin(node)
        finally:
            a._acc = None
        selfesc = [f for f in found if f["category"] == "self-escalation" and f["grants_admin"]]
        open_selfesc = [f for f in selfesc if not f.get("requires")]
        selfesc_reason = "can grant itself any permission (" + ", ".join(f["id"] for f in selfesc) + ")"
        # Admin if allowed everything or able to grant itself anything. When both, and only one
        # of them needs MFA, a network location or a time window, the open one is the answer:
        # the principal is admin without the condition.
        if full and not gates:
            admin[arn] = FULL_ADMIN
        elif open_selfesc:
            admin[arn] = selfesc_reason
        elif full:
            admin[arn] = FULL_ADMIN
            admin_gates[arn] = frozenset(gates)
        elif selfesc:
            admin[arn] = selfesc_reason
            admin_gates[arn] = frozenset((r["kind"], r["key"], r["value"]) for r in selfesc[0]["requires"])
        else:
            admin[arn] = None

    # Explore from the start (or everything), following confirmed edges.
    roots = [start] if start else sorted(env.nodes)
    queue = deque(roots)
    order: list[str] = []
    while queue:
        arn = queue.popleft()
        if arn in techniques:
            continue
        visit(arn)
        order.append(arn)
        for e in edges[arn]:
            if e.target not in techniques:
                queue.append(e.target)

    paths = _paths(roots, edges, admin, admin_gates)
    report: dict[str, Any] = {
        "start": start,
        "principals": [
            {
                "arn": arn,
                "kind": env.nodes[arn].kind,
                "admin_equivalent": admin[arn] is not None,
                "admin_reason": admin[arn],
                **({"admin_requires": describe(admin_gates[arn])} if admin_gates.get(arn) else {}),
                "techniques": techniques[arn],
            }
            for arn in order
        ],
        "paths": paths,
        "warnings": env.warnings + (env.resources.warnings if env.resources else []),
        "inventory": env.resources.summary() if env.resources else None,
        "blast_radius": None,
    }
    if catalog is not None:
        reach = order if start else []
        report["blast_radius"] = _blast_radius(a, [env.nodes[x] for x in reach], catalog) if reach else None
    return report


def _paths(
    roots: list[str],
    edges: dict[str, list[Edge]],
    admin: dict[str, str | None],
    admin_gates: dict[str, frozenset[Gate]] | None = None,
) -> list[dict[str, Any]]:
    """The shortest path from each root to each admin-equivalent principal it reaches.

    Open steps (no gate) are searched first, so an open path is found even when a shorter gated
    one exists; ends reachable only through gated steps get the shortest gated path. Each path
    lists what it requires: the gates of its steps and of the admin access at its end.
    """
    admin_gates = admin_gates or {}
    out: list[dict[str, Any]] = []
    for root in roots:
        if admin.get(root) and not admin_gates.get(root):
            continue  # already admin-equivalent; no path needed
        found_ends: set[str] = set()
        for open_only in (True, False):
            prev: dict[str, Edge | None] = {root: None}
            q = deque([root])
            while q:
                cur = q.popleft()
                for e in edges.get(cur, []):
                    if e.target in prev or (open_only and e.gates):
                        continue
                    prev[e.target] = e
                    if (admin.get(e.target) or e.grants_admin) and e.target not in found_ends:
                        found_ends.add(e.target)
                        chain: list[Edge] = []
                        node: str = e.target
                        while prev[node] is not None:
                            edge = prev[node]
                            assert edge is not None
                            chain.append(edge)
                            node = edge.source
                        chain.reverse()
                        end_gates = admin_gates.get(e.target, frozenset()) if not e.grants_admin else frozenset()
                        gates = frozenset().union(*(x.gates for x in chain)) | end_gates
                        out.append(
                            {
                                "start": root,
                                "end": e.target,
                                "end_admin": True,
                                "why": admin.get(e.target) or "the last step lets the attacker grant it any permission",
                                "steps": [
                                    {
                                        "from": x.source,
                                        "to": x.target,
                                        "technique": x.technique,
                                        "name": x.name,
                                        **({"requires": describe(x.gates)} if x.gates else {}),
                                    }
                                    for x in chain
                                ],
                                "open": not gates,
                                "requires": describe(gates),
                            }
                        )
                    # Past an admin-equivalent principal there is nothing more to gain.
                    if e.target in edges and not (admin.get(e.target) and not admin_gates.get(e.target)):
                        q.append(e.target)
    out.sort(key=lambda p: (p["start"], not p["open"], len(p["steps"]), p["end"]))
    return out


def _blast_radius(a: _Analyzer, nodes: list[Node], catalog: Catalog) -> dict[str, Any]:
    allowed: dict[str, str] = {}
    for n in nodes:
        for info in catalog.all_actions():
            if info.full_name in allowed:
                continue
            if a.can(n, info.full_name, "*"):
                allowed[info.full_name] = info.access_level
    counts = {lvl: 0 for lvl in ACCESS_LEVELS}
    for lvl in allowed.values():
        counts[lvl] += 1
    return {
        "principals": [n.arn for n in nodes],
        "note": 'actions allowed on Resource "*" by any reachable principal; resource-scoped grants are not counted',
        "actions_by_access_level": {k: v for k, v in counts.items() if v},
        "permissions_management_actions": sorted(k for k, v in allowed.items() if v == "Permissions management"),
        "total_actions": len(allowed),
    }


# --- rendering ---------------------------------------------------------------------------------


def _short(arn: str) -> str:
    return arn.split(":", 5)[-1] if arn.startswith("arn:") else arn


def escalate_text(r: dict[str, Any]) -> str:
    lines: list[str] = []
    for p in r["principals"]:
        lines.append(f"Principal {p['arn']}")
        lines.append(f"  Admin-equivalent: {'yes, ' + p['admin_reason'] if p['admin_equivalent'] else 'no'}")
        if p.get("admin_requires"):
            lines.append(f"      only when {'; '.join(x['text'] for x in p['admin_requires'])}")
        if not p["techniques"]:
            lines.append("  No known escalation technique is allowed.")
        if p["admin_equivalent"] and p["admin_reason"] == FULL_ADMIN:
            # Every technique applies; listing all of them adds nothing. JSON output keeps them.
            lines.append(f"  {len(p['techniques'])} techniques apply to it (use --format json to list them).")
            lines.append("")
            continue
        for t in p["techniques"]:
            lines.append(f"  {t['id']:<18} {t['name']}  [{t['category']}, {t['confidence']}]")
            lines.append(f"      targets: {', '.join(t['targets'])}")
            if t.get("via"):
                lines.append(f"      via:     {', '.join(t['via'])}")
            if t.get("requires"):
                lines.append(f"      only when {'; '.join(x['text'] for x in t['requires'])}")
            src = t["source"]
            lines.append(f"      source:  {src['pathfinding']}")
            if src.get("first_documented"):
                lines.append(f"               first documented by {src['author']}: {src['first_documented']}")
        lines.append("")
    if r["paths"]:
        lines.append("Escalation paths")
        for i, path in enumerate(r["paths"], 1):
            chain = _short(path["start"])
            for s in path["steps"]:
                chain += f" --[{s['technique']}]--> {_short(s['to'])}"
            gate = summary((x["kind"], x["key"], x["value"]) for x in path.get("requires", []))
            lines.append(f"  {i}. {chain}  [{gate}]")
            lines.append(f"     {path['why']}")
            if path.get("requires"):
                lines.append(f"     only when {'; '.join(x['text'] for x in path['requires'])}")
    elif r["start"]:
        lines.append("Escalation paths: none found to an admin-equivalent principal.")
    if r.get("new_findings") is not None:
        lines += ["", f"New compared with the baseline: {len(r['new_findings'])}"]
        lines += [f"  {f['id']} {f['name']}" for f in r["new_findings"]]
    br = r.get("blast_radius")
    if br:
        lines += [
            "",
            f'Blast radius ({len(br["principals"])} reachable principal(s), {br["total_actions"]} actions on "*")',
        ]
        lines += [f"  {k}: {v}" for k, v in br["actions_by_access_level"].items()]
        lines.append(f"  ({br['note']})")
    inv = r.get("inventory")
    if inv is not None:
        counts = ", ".join(f"{n} {k}" for k, n in inv.items()) or "no kinds collected"
        lines += ["", f"Resource inventory: {counts}."]
    if r["warnings"]:
        lines += ["", "Warnings:"] + [f"  - {w}" for w in r["warnings"]]
    return "\n".join(lines).rstrip() + "\n"


def escalate_sarif(r: dict[str, Any]) -> str:
    rules: dict[str, dict[str, Any]] = {}
    results = []
    for p in r["principals"]:
        for t in p["techniques"]:
            rules.setdefault(
                t["id"],
                {
                    "id": t["id"],
                    "name": t["name"],
                    "shortDescription": {"text": f"Privilege escalation: {t['name']}"},
                    "helpUri": t["source"]["pathfinding"],
                },
            )
            results.append(
                {
                    "ruleId": t["id"],
                    "level": "error" if t["confidence"] == "confirmed" else "warning",
                    "message": {
                        "text": f"{p['arn']} can use {t['name']} ({t['category']}, {t['confidence']}) "
                        f"on {', '.join(t['targets'])}"
                    },
                }
            )
    for path in r["paths"]:
        rules.setdefault(
            "path", {"id": "path", "shortDescription": {"text": "Escalation path to an admin-equivalent principal"}}
        )
        chain = " -> ".join([path["start"]] + [s["to"] for s in path["steps"]])
        results.append({"ruleId": "path", "level": "error", "message": {"text": f"Escalation path: {chain}"}})
    return sarif_log(list(rules.values()), results)
