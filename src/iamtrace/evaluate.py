"""The decision engine.

It implements the order in "How AWS enforcement code logic evaluates requests to allow or deny
access":
https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html

    1. explicit_deny        any applicable Deny in any policy -> Deny
    2. rcp                  every RCP level must allow (resource owner's account)
    3. scp                  every SCP level must allow (principal's account)
    4. resource_policy      an Allow can be final within one account, depending on whom it names
    5. identity_policy      identity policies must allow
    6. permissions_boundary the boundary must allow
    7. session_policy       session policies must allow

Cross-account requests (https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic-cross-account.html):
"The request is allowed only if both evaluations return a decision of Allow." Steps 5 to 7 form
the identity side; step 4 forms the resource side and must allow on its own.

Every Result carries a trace: one entry per step that was evaluated, each listing the statements
that matched. `deciding_step` is the step where evaluation stopped.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from iamtrace.arn import account_of, resource_matches, service_of_action
from iamtrace.conditions import evaluate_condition_block
from iamtrace.context import Context
from iamtrace.matching import any_action_matches
from iamtrace.model import Policy, PolicyType, Statement
from iamtrace.principals import GrantKind, Principal, match_principal_element, not_principal_excludes
from iamtrace.servicerules import RCP_EXEMPT_ACTIONS, RCP_SERVICES, resource_policy_required


class Decision(StrEnum):
    ALLOW = "Allow"
    EXPLICIT_DENY = "ExplicitDeny"
    IMPLICIT_DENY = "ImplicitDeny"


@dataclass(frozen=True)
class MatchedStatement:
    policy_id: str
    policy_type: str
    statement: str  # Sid, or Statement[i]
    index: int
    effect: str
    sid: str | None
    grant: str | None = None  # resource policies: direct | role | account
    conditions: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "policy": self.policy_id,
            "policy_type": self.policy_type,
            "statement": self.statement,
            "index": self.index,
            "effect": self.effect,
        }
        if self.grant:
            d["grant"] = self.grant
        if self.conditions:
            d["conditions"] = list(self.conditions)
        return d


@dataclass
class TraceStep:
    step: str
    outcome: str  # "deny" | "allow" | "pass" | "not applicable" | "no match"
    detail: str
    matches: list[MatchedStatement] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "step": self.step,
            "outcome": self.outcome,
            "detail": self.detail,
            "matches": [m.to_dict() for m in self.matches],
        }


@dataclass(frozen=True)
class Request:
    principal: Principal
    action: str
    resource: str = "*"
    resource_account: str | None = None
    context: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class PolicySet:
    identity: list[Policy] = field(default_factory=list)
    resource: list[Policy] = field(default_factory=list)
    boundary: Policy | None = None
    session: list[Policy] = field(default_factory=list)
    # Organizations policies by level, root first: [[root policies], [OU policies], ..., [account policies]].
    # None means the account is not in an organization (or the caller did not supply them).
    scps: list[list[Policy]] | None = None
    rcps: list[list[Policy]] | None = None
    # The principal's account is the organization's management account (SCPs don't apply).
    scp_exempt: bool = False
    # The resource is in the management account (RCPs don't apply).
    rcp_exempt: bool = False
    # The resource is an AWS managed KMS key (RCPs don't apply).
    resource_is_aws_managed_key: bool = False

    def all_policies(self) -> Iterable[Policy]:
        yield from self.identity
        yield from self.resource
        if self.boundary:
            yield self.boundary
        yield from self.session
        for level in self.scps or []:
            yield from level
        for level in self.rcps or []:
            yield from level


@dataclass
class Result:
    decision: Decision
    deciding_step: str
    trace: list[TraceStep]
    warnings: list[str]
    request: Request
    effective_context: dict[str, Any] = field(default_factory=dict)

    @property
    def allowed(self) -> bool:
        return self.decision is Decision.ALLOW

    def to_dict(self) -> dict[str, Any]:
        p = self.request.principal
        return {
            "decision": self.decision.value,
            "deciding_step": self.deciding_step,
            "request": {
                "principal": p.describe(),
                "action": self.request.action,
                "resource": self.request.resource,
                "resource_account": self.request.resource_account,
                "context": self.effective_context,
            },
            "trace": [t.to_dict() for t in self.trace],
            "warnings": self.warnings,
        }


# --- statement matching ----------------------------------------------------------


@dataclass(frozen=True)
class _Match:
    statement: Statement
    policy: Policy
    grant: GrantKind | None
    conditions: tuple[str, ...]

    def record(self) -> MatchedStatement:
        s = self.statement
        return MatchedStatement(
            policy_id=self.policy.id,
            policy_type=self.policy.type.value,
            statement=s.label,
            index=s.index,
            effect=s.effect,
            sid=s.sid,
            grant=self.grant.value if self.grant else None,
            conditions=self.conditions,
        )


def _applies(s: Statement, policy: Policy, req: Request, ctx: Context, has_boundary: bool) -> _Match | None:
    # Action / NotAction
    if s.actions is not None:
        if not any_action_matches(s.actions, req.action):
            return None
    elif s.not_actions is not None and any_action_matches(s.not_actions, req.action):
        return None
    # Resource / NotResource. A resource-based policy may omit Resource (trust policies do);
    # then the statement applies to the resource the policy is attached to.
    v = policy.variables_enabled
    if s.resources is not None:
        if not any(resource_matches(r, req.resource, ctx, v) for r in s.resources):
            return None
    elif s.not_resources is not None:
        if any(resource_matches(r, req.resource, ctx, v) for r in s.not_resources):
            return None
    # Principal / NotPrincipal (resource-based policies and RCPs)
    grant: GrantKind | None = None
    if policy.type in (PolicyType.RESOURCE, PolicyType.RCP):
        if s.principal is not None:
            grant = match_principal_element(s.principal, req.principal)
            if grant is None:
                return None
        elif s.not_principal is not None:
            if not_principal_excludes(s.not_principal, req.principal, has_boundary=has_boundary):
                return None
            grant = GrantKind.DIRECT
        else:
            grant = GrantKind.DIRECT  # RCP statements without Principal apply to everyone
    cond = evaluate_condition_block(s.condition, ctx, v)
    if not cond.matched:
        return None
    return _Match(s, policy, grant, cond.details)


def _matches(policies: Iterable[Policy], effect: str, req: Request, ctx: Context, has_boundary: bool) -> list[_Match]:
    out = []
    for p in policies:
        for s in p.statements:
            if s.effect != effect:
                continue
            m = _applies(s, p, req, ctx, has_boundary)
            if m:
                out.append(m)
    return out


_GRANT_ORDER = {GrantKind.DIRECT: 3, GrantKind.ROLE: 2, GrantKind.ACCOUNT: 1}


def _best_grant(matches: list[_Match]) -> GrantKind | None:
    grants = [m.grant for m in matches if m.grant is not None]
    return max(grants, key=lambda g: _GRANT_ORDER[g]) if grants else None


# --- context ----------------------------------------------------------------------


def _build_context(req: Request, resource_account: str | None) -> Context:
    """Start from the caller's context and add keys AWS always sets, unless already given."""
    ctx = Context(req.context)
    p = req.principal
    if p.principal_arn:
        ctx.setdefault_value("aws:PrincipalArn", p.principal_arn)
    if p.account:
        ctx.setdefault_value("aws:PrincipalAccount", p.account)
    if p.principal_type:
        ctx.setdefault_value("aws:PrincipalType", p.principal_type)
    if p.username:
        ctx.setdefault_value("aws:username", p.username)
    if p.kind == "service" and p.service_name:
        ctx.setdefault_value("aws:PrincipalServiceName", p.service_name)
    if resource_account:
        ctx.setdefault_value("aws:ResourceAccount", resource_account)
    return ctx


# --- evaluation -------------------------------------------------------------------


def evaluate(req: Request, policies: PolicySet) -> Result:
    p = req.principal
    trace: list[TraceStep] = []
    warnings: list[str] = []
    for pol in policies.all_policies():
        warnings.extend(f"{pol.id}: {w}" for w in pol.warnings)

    resource_account = req.resource_account or account_of(req.resource)
    if resource_account is None and p.account:
        resource_account = p.account
        warnings.append(
            "resource account unknown (the ARN has no account); assuming the principal's account. "
            "Pass the resource account to evaluate cross-account access."
        )
    ctx = _build_context(req, resource_account)

    def done(decision: Decision) -> Result:
        return Result(decision, trace[-1].step, trace, warnings, req, ctx.as_dict())

    has_identity = p.has_identity_policies
    boundary = policies.boundary if has_identity else None
    if policies.boundary is not None and not has_identity:
        warnings.append(f"permissions boundary ignored: a {p.kind} principal has none")
    sessions = policies.session if p.is_session else []
    if policies.session and not p.is_session:
        warnings.append("session policies ignored: the principal is not a session")
    identity = policies.identity if has_identity else []
    if policies.identity and not has_identity:
        warnings.append(f"identity policies ignored: a {p.kind} principal has none")
    has_boundary = boundary is not None

    service = service_of_action(req.action)
    scp_levels, scp_reason = _org_levels(
        policies.scps,
        [
            (policies.scp_exempt, "principal is in the management account"),
            (
                p.kind not in ("user", "role_session", "federated_user", "root"),
                f"SCPs do not apply to a {p.kind} principal",
            ),
            (p.is_service_linked_role, "SCPs do not apply to service-linked roles"),
        ],
    )
    rcp_levels, rcp_reason = _org_levels(
        policies.rcps,
        [
            (policies.rcp_exempt, "resource is in the management account"),
            (service not in RCP_SERVICES, f"RCPs do not apply to {service} actions"),
            (req.action.lower() in RCP_EXEMPT_ACTIONS, f"RCPs do not apply to {req.action}"),
            (p.is_service_linked_role, "RCPs do not restrict service-linked roles"),
            (policies.resource_is_aws_managed_key, "RCPs do not apply to AWS managed KMS keys"),
        ],
    )

    # Step 1: explicit deny ------------------------------------------------------
    deny_scope: list[Policy] = [*identity, *policies.resource, *sessions]
    if boundary:
        deny_scope.append(boundary)
    for level in scp_levels or []:
        deny_scope.extend(level)
    for level in rcp_levels or []:
        deny_scope.extend(level)
    denies = _matches(deny_scope, "Deny", req, ctx, has_boundary)
    if denies:
        trace.append(
            TraceStep("explicit_deny", "deny", "an applicable Deny statement was found", [m.record() for m in denies])
        )
        return done(Decision.EXPLICIT_DENY)
    trace.append(TraceStep("explicit_deny", "pass", "no applicable Deny statement"))

    # Steps 2 and 3: RCPs and SCPs ------------------------------------------------
    for step, levels, reason, owner in (
        ("rcp", rcp_levels, rcp_reason, "resource owner"),
        ("scp", scp_levels, scp_reason, "principal"),
    ):
        if levels is None:
            if reason:
                trace.append(TraceStep(step, "not applicable", reason))
            continue
        all_matches: list[MatchedStatement] = []
        for i, level in enumerate(levels):
            allows = _matches(level, "Allow", req, ctx, has_boundary)
            if not allows:
                trace.append(
                    TraceStep(
                        step,
                        "deny",
                        f"no Allow at organization level {i} (0 is the root) for the {owner}'s account",
                        all_matches,
                    )
                )
                return done(Decision.IMPLICIT_DENY)
            all_matches.extend(m.record() for m in allows)
        trace.append(TraceStep(step, "pass", f"every level allows ({len(levels)} levels)", all_matches))

    # Gather the remaining inputs -------------------------------------------------
    res_allows = _matches(policies.resource, "Allow", req, ctx, has_boundary)
    grant = _best_grant(res_allows)
    res_records = [m.record() for m in res_allows]
    required = resource_policy_required(req.action, req.resource)
    same_account = p.account is None or p.account == resource_account

    def boundary_step() -> bool:
        if boundary is None:
            return True
        allows = _matches([boundary], "Allow", req, ctx, has_boundary)
        if not allows:
            trace.append(
                TraceStep("permissions_boundary", "deny", "the permissions boundary does not allow the action")
            )
            return False
        trace.append(
            TraceStep(
                "permissions_boundary",
                "pass",
                "the permissions boundary allows the action",
                [m.record() for m in allows],
            )
        )
        return True

    def session_step() -> bool:
        if not sessions:
            return True
        allows = _matches(sessions, "Allow", req, ctx, has_boundary)
        if not allows:
            trace.append(TraceStep("session_policy", "deny", "no session policy allows the action"))
            return False
        trace.append(
            TraceStep("session_policy", "pass", "a session policy allows the action", [m.record() for m in allows])
        )
        return True

    def identity_step() -> bool:
        if p.kind == "root":
            trace.append(
                TraceStep(
                    "identity_policy", "pass", "the account root user needs no identity policy in its own account"
                )
            )
            return True
        allows = _matches(identity, "Allow", req, ctx, has_boundary)
        if not allows:
            detail = "no identity-based policy allows the action"
            if not has_identity:
                detail = f"a {p.kind} principal has no identity-based policies"
            trace.append(TraceStep("identity_policy", "deny", detail))
            return False
        trace.append(
            TraceStep(
                "identity_policy", "pass", "an identity-based policy allows the action", [m.record() for m in allows]
            )
        )
        return True

    # Cross-account -----------------------------------------------------------------
    if not same_account:
        # Identity side, in the principal's account.
        if not identity_step() or not boundary_step() or not session_step():
            trace[-1].detail += " (trusted account side of a cross-account request)"
            return done(Decision.IMPLICIT_DENY)
        # Resource side, in the resource owner's account.
        if grant is None:
            detail = (
                f"cross-account request: no resource-based policy in account {resource_account} allows {p.describe()}"
            )
            if not policies.resource:
                detail += " (none was supplied)"
            trace.append(TraceStep("resource_policy", "deny", detail))
            return done(Decision.IMPLICIT_DENY)
        trace.append(
            TraceStep(
                "resource_policy",
                "allow",
                f"cross-account request: both accounts allow (resource grant: {grant.value})",
                res_records,
            )
        )
        return done(Decision.ALLOW)

    # Same account ----------------------------------------------------------------------
    if grant is GrantKind.DIRECT:
        trace.append(
            TraceStep(
                "resource_policy",
                "allow",
                "a resource-based policy grants access directly to this principal; an implicit deny in "
                "identity policies, boundaries or session policies does not limit it",
                res_records,
            )
        )
        return done(Decision.ALLOW)

    if grant is GrantKind.ROLE:
        trace.append(
            TraceStep(
                "resource_policy",
                "pass",
                "a resource-based policy grants access to the role (or the federating user); no identity "
                "policy is needed, but the boundary and session policies must allow",
                res_records,
            )
        )
        if not boundary_step() or not session_step():
            return done(Decision.IMPLICIT_DENY)
        return done(Decision.ALLOW)

    if required and grant is None:
        detail = f"the {required} must explicitly allow this principal"
        if not policies.resource:
            detail += " (none was supplied)"
        trace.append(TraceStep("resource_policy", "deny", detail))
        return done(Decision.IMPLICIT_DENY)

    if grant is GrantKind.ACCOUNT:
        trace.append(
            TraceStep(
                "resource_policy",
                "pass",
                "a resource-based policy names the account, which delegates to IAM: an identity policy must allow",
                res_records,
            )
        )
    elif not has_identity and p.kind != "root":
        trace.append(TraceStep("resource_policy", "deny", f"no resource-based policy allows this {p.kind} principal"))
        return done(Decision.IMPLICIT_DENY)
    else:
        trace.append(
            TraceStep(
                "resource_policy",
                "no match",
                "no resource-based policy allows the action"
                if policies.resource
                else "no resource-based policy supplied",
            )
        )

    if not identity_step() or not boundary_step() or not session_step():
        return done(Decision.IMPLICIT_DENY)
    return done(Decision.ALLOW)


def _org_levels(
    levels: list[list[Policy]] | None, exemptions: list[tuple[bool, str]]
) -> tuple[list[list[Policy]] | None, str | None]:
    if levels is None:
        return None, None
    for exempt, reason in exemptions:
        if exempt:
            return None, reason
    return levels, None
