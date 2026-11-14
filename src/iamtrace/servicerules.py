"""Service-specific facts the evaluation needs.

Keep this file small and sourced. Each entry cites the AWS page it comes from, and
docs/limitations.md says what is not covered.
"""

from __future__ import annotations

from iamtrace.arn import Arn

# Services whose actions RCPs apply to. Copied from "Resource control policies (RCPs)":
# https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_policies_rcps.html
# (85 service prefixes as of November 2026.)
RCP_SERVICES: frozenset[str] = frozenset(
    [
        "appflow",
        "app-integrations",
        "appstream",
        "dsql",
        "clouddirectory",
        "cloudfront",
        "cloudsearch",
        "cloudwatch",
        "internetmonitor",
        "logs",
        "networkmonitor",
        "rum",
        "cognito-identity",
        "cognito-idp",
        "comprehend",
        "comprehendmedical",
        "firehose",
        "devops-guru",
        "dynamodb",
        "dax",
        "autoscaling",
        "ebs",
        "ecr",
        "ecr-public",
        "elasticfilesystem",
        "schemas",
        "gamelift",
        "inspector-scan",
        "kendra",
        "kinesisvideo",
        "lexv2-runtime",
        "macie2",
        "managedblockchain",
        "grafana",
        "memorydb",
        "aoss",
        "personalize",
        "polly",
        "s3",
        "securitylake",
        "sns",
        "swf",
        "sqs",
        "textract",
        "timestream-influxdb",
        "transcribe",
        "translate",
        "workspaces",
        "amplify",
        "appconfig",
        "application-autoscaling",
        "auditmanager",
        "autoscaling-plans",
        "budgets",
        "cleanrooms",
        "servicediscovery",
        "cloudtrail-data",
        "codeartifact",
        "codebuild",
        "codecommit",
        "codepipeline",
        "compute-optimizer",
        "cost-optimization-hub",
        "events",
        "fms",
        "fis",
        "health",
        "rolesanywhere",
        "kms",
        "refactor-spaces",
        "opensearch",
        "pricing",
        "pca-connector-ad",
        "acm-pca",
        "resiliencehub",
        "resource-groups",
        "secretsmanager",
        "sts",
        "signin",
        "signer",
        "support",
        "transfer",
        "notifications",
        "wafv2",
        "xray",
    ]
)

# "RCPs do not impact the kms:RetireGrant permission." (same page)
RCP_EXEMPT_ACTIONS: frozenset[str] = frozenset({"kms:retiregrant"})

# STS actions that are authorized against a role's trust policy.
_TRUST_ACTIONS = frozenset(
    {
        "sts:assumerole",
        "sts:assumerolewithsaml",
        "sts:assumerolewithwebidentity",
        "sts:tagsession",
        "sts:setsourceidentity",
        "sts:setcontext",
    }
)


def resource_policy_required(action: str, resource: str) -> str | None:
    """Name the resource policy that must explicitly allow this request, or None.

    "IAM role trust policies and KMS key policies are exceptions to this logic, because they
    must explicitly allow access for principals."
    https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_evaluation-logic_policy-eval-denyallow.html

    Other services may also require an explicit allow in their resource policy. iam-trace does
    not model those; see docs/limitations.md.
    """
    arn = Arn.parse(resource)
    if arn is None:
        return None
    a = action.lower()
    if a in _TRUST_ACTIONS and arn.service == "iam" and arn.resource.startswith("role/"):
        return "role trust policy"
    if a.startswith("kms:") and arn.service == "kms" and arn.resource.startswith("key/"):
        return "KMS key policy"
    return None
