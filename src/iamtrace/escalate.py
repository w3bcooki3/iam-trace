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
"""

from __future__ import annotations

import json
import urllib.parse
from collections import deque
from dataclasses import dataclass, field
from functools import cache
from importlib import resources
from typing import Any

from iamtrace.arn import resource_matches
from iamtrace.catalog import ACCESS_LEVELS, Catalog
from iamtrace.context import Context
from iamtrace.evaluate import PolicySet, Request, evaluate
from iamtrace.inventory import TECHNIQUE_KIND, Inventory
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy, PolicyError, PolicyType
from iamtrace.output import sarif_log
from iamtrace.principals import Principal

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
}

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

    @property
    def account(self) -> str:
        return self.arn.split(":")[4]

    def caller(self) -> Principal:
        return Principal.from_arn(self.arn)


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
            nodes[u["Arn"]] = Node(u["Arn"], "user", policies, boundary(u, label), groups=gl, attached=arns)
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
            )
        return cls(nodes, group_arns, warnings, raw=data)

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


class _Analyzer:
    def __init__(self, env: Environment, scps: list[list[Policy]] | None) -> None:
        self.env = env
        self.scps = scps
        self._cache: dict[tuple[str, str, str, str], bool] = {}
        self._may: dict[tuple[str, str], bool] = {}
        self._trust: dict[tuple[str, str], bool] = {}
        self._patterns: dict[str, tuple[str, ...] | None] = {}

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
            json.dumps(context or {}, sort_keys=True) + (trust.id if trust else ""),
        )
        if key not in self._cache:
            # The resource's own account when its ARN has one (S3 ARNs do not), else the caller's.
            parts = resource.split(":", 5)
            account = parts[4] if len(parts) > 4 and parts[0] == "arn" and parts[4] else node.account
            req = Request(node.caller(), action, resource, resource_account=account, context=context or {})
            ps = PolicySet(
                identity=node.policies, boundary=node.boundary, scps=self.scps, resource=[trust] if trust else []
            )
            self._cache[key] = evaluate(req, ps).allowed
        return self._cache[key]

    def may_allow(self, node: Node, action: str) -> bool:
        """Cheap over-approximation: can any of the node's Allow statements cover this action?

        If not, no resource and no condition can make the identity policies allow it, so the
        expensive per-target checks are skipped. sts:AssumeRole is the exception: a role's trust
        policy can grant it directly, so it is always checked per target.
        """
        a = action.lower()
        if a == "sts:assumerole":
            return True
        key = (node.arn, a)
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
        return any(self.can(node, action, r, context=context) for r in self.candidates(node, action))

    def is_admin(self, node: Node) -> bool:
        return self.can(node, ADMIN_PROBE, "*")

    # -- targets ---------------------------------------------------------------------

    def targets(self, node: Node, ttype: str, *, others: bool) -> list[str]:
        env = self.env
        if ttype in ("user", "role"):
            arns = [a for a, n in env.nodes.items() if n.kind == ttype and (a != node.arn or not others)]
        elif ttype == "group":
            arns = list(env.groups)
        else:
            arns = []
        return sorted(arns)

    def trusted_by_service(self, role: Node, service: str) -> bool:
        if role.trust is None:
            return False
        key = (role.arn, service)
        if key not in self._trust:
            req = Request(Principal.service(service), "sts:AssumeRole", role.arn, resource_account=role.account)
            self._trust[key] = evaluate(req, PolicySet(resource=[role.trust])).allowed
        return self._trust[key]

    # -- techniques --------------------------------------------------------------------

    def techniques(self, node: Node) -> tuple[list[dict[str, Any]], list[Edge]]:
        found: list[dict[str, Any]] = []
        edges: list[Edge] = []
        for t in technique_catalog():
            result = self._check(node, t)
            if result is None:
                continue
            # (targets, confidence, grants_admin, edge_targets[, via]): via names the existing
            # resources an inventory-backed finding goes through.
            targets, confidence, grants_admin, edge_targets = result[:4]
            via: list[str] = list(result[4]) if len(result) > 4 else []
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
                edges.append(Edge(node.arn, target, t["id"], t["name"], grants_admin))
        return found, edges

    def _perm_ok(
        self, node: Node, perm: str, target: Node | str | None, extra_ctx: dict[str, Any] | None = None
    ) -> bool:
        ptype = PERMISSION_TARGET.get(perm.lower())
        tnode = target if isinstance(target, Node) else None
        if ptype in ("user", "role") and tnode is not None:
            trust = tnode.trust if perm.lower() == "sts:assumerole" else None
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
                if all(self._perm_ok(node, p, tnode) for p in perms):
                    hits.append(arn)
            return (hits, "confirmed", grants_admin, hits) if hits else None

        service = tid.rsplit("-", 1)[0]
        svc_principal = SERVICE_PRINCIPALS.get(service)
        if cat == "new-passrole":
            others = [p for p in perms if p.lower() != "iam:passrole"]
            if not all(self.any_allowed(node, p) for p in others):
                return None
            ctx = {"iam:PassedToService": svc_principal} if svc_principal else {}
            if not env.inventory:
                if self.any_allowed(node, "iam:PassRole", ctx):
                    return (["any role the policy lets it pass"], "possible", False, [])
                return None
            hits, possible = [], []
            for arn in self.targets(node, "role", others=True):
                tnode = env.nodes[arn]
                if not self.can(node, "iam:PassRole", arn, context=ctx):
                    continue
                if svc_principal is None:
                    possible.append(arn)
                elif self.trusted_by_service(tnode, svc_principal):
                    hits.append(arn)
            if hits:
                return (hits, "confirmed", False, hits)
            if possible:
                return (possible, "possible", False, [])
            return None

        if cat == "existing-passrole":
            kind = TECHNIQUE_KIND.get(tid)
            inv = env.resources
            if inv is not None and kind in inv.collected:
                return self._existing(node, perms, inv, kind)
            if not all(self.any_allowed(node, p) for p in perms):
                return None
            roles = [
                a
                for a in self.targets(node, "role", others=True)
                if svc_principal and self.trusted_by_service(self.env.nodes[a], svc_principal)
            ]
            label = roles or [f"existing {service} resources and the roles attached to them (not in the IAM export)"]
            return (label, "possible", False, [])
        return None

    def _existing(self, node: Node, perms: list[str], inv: Inventory, kind: str) -> tuple[Any, ...] | None:
        """Check an existing-resource technique against each inventoried resource of its kind."""
        roles: set[str] = set()
        via: set[str] = set()
        decided: dict[tuple[str, ...], bool] = {}
        patterns = self._resource_patterns(node)
        for r in inv.of_kind(kind):
            if r.role is None or r.role == node.arn:
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
                decided[sig] = all(self.can(node, p, r.arn) for p in perms)
            if decided[sig]:
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
        targets: list[str]
        if ttype == "policy":
            customer = [a for a in self._attached(node) if ":iam::aws:policy/" not in a]
            if not env.inventory:
                customer = self.candidates(node, main)
            targets = [a for a in customer if self.can(node, main, a)]
        elif ttype in ("user", "role"):
            targets = [node.arn] if node.kind == ttype and self.can(node, main, node.arn) else []
        elif ttype == "group":
            if main == "iam:addusertogroup":
                if node.kind != "user":
                    return None
                pool = list(env.groups) if env.inventory else self.candidates(node, main)
            else:
                pool = node.groups if env.inventory else self.candidates(node, main)
            targets = [g for g in pool if self.can(node, main, g)]
        else:
            targets = []
        if not targets:
            return None
        confidence = "confirmed" if env.inventory else "possible"
        return (sorted(targets), confidence, True, [])

    def _attached(self, node: Node) -> list[str]:
        return node.attached


def analyze(
    env: Environment,
    start: str | None = None,
    *,
    catalog: Catalog | None = None,
    scps: list[list[Policy]] | None = None,
) -> dict[str, Any]:
    a = _Analyzer(env, scps)
    if start is not None and start not in env.nodes:
        raise ValueError(f"{start} is not in the account export")

    techniques: dict[str, list[dict[str, Any]]] = {}
    edges: dict[str, list[Edge]] = {}
    admin: dict[str, str | None] = {}

    def visit(arn: str) -> None:
        if arn in techniques:
            return
        node = env.nodes[arn]
        found, out = a.techniques(node)
        techniques[arn] = found
        edges[arn] = out
        if a.is_admin(node):
            admin[arn] = FULL_ADMIN
        elif any(f["category"] == "self-escalation" for f in found):
            admin[arn] = (
                "can grant itself any permission ("
                + ", ".join(f["id"] for f in found if f["category"] == "self-escalation")
                + ")"
            )
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

    paths = _paths(roots, edges, admin)
    report: dict[str, Any] = {
        "start": start,
        "principals": [
            {
                "arn": arn,
                "kind": env.nodes[arn].kind,
                "admin_equivalent": admin[arn] is not None,
                "admin_reason": admin[arn],
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


def _paths(roots: list[str], edges: dict[str, list[Edge]], admin: dict[str, str | None]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for root in roots:
        if admin.get(root):
            continue  # already admin-equivalent; no path needed
        prev: dict[str, Edge | None] = {root: None}
        q = deque([root])
        while q:
            cur = q.popleft()
            for e in edges.get(cur, []):
                if e.target in prev:
                    continue
                prev[e.target] = e
                if admin.get(e.target) or e.grants_admin:
                    steps = []
                    node: str = e.target
                    while prev[node] is not None:
                        edge = prev[node]
                        assert edge is not None
                        steps.append(
                            {"from": edge.source, "to": edge.target, "technique": edge.technique, "name": edge.name}
                        )
                        node = edge.source
                    steps.reverse()
                    out.append(
                        {
                            "start": root,
                            "end": e.target,
                            "end_admin": True,
                            "why": admin.get(e.target) or "the last step lets the attacker grant it any permission",
                            "steps": steps,
                        }
                    )
                if e.target in edges:
                    q.append(e.target)
    out.sort(key=lambda p: (p["start"], len(p["steps"]), p["end"]))
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
            lines.append(f"  {i}. {chain}")
            lines.append(f"     {path['why']}")
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
