"""Synthetic service reference data for offline tests.

These dictionaries have the shape AWS documents for the machine-readable Service Authorization
Reference (Name, ServiceName, Actions[].Annotations.Properties, Resources, ConditionKeys). The
action list is a small hand-picked subset and the flags are written from the HTML reference by
hand. They exist to test iam-trace, not to describe AWS: the real catalog comes from
`iam-trace catalog refresh`.

Flag letters: P = IsPermissionManagement, T = IsTaggingOnly, W = IsWrite, L = IsList,
R = read (no flag set). PassRole is "W", matching the real JSON.
"""

from __future__ import annotations

from typing import Any

SERVICES: dict[str, dict[str, str]] = {
    "iam": {
        "AddUserToGroup": "PW",
        "AttachGroupPolicy": "PW",
        "AttachRolePolicy": "PW",
        "AttachUserPolicy": "PW",
        "CreateAccessKey": "PW",
        "CreateLoginProfile": "PW",
        "CreatePolicy": "PW",
        "CreatePolicyVersion": "PW",
        "CreateRole": "PW",
        "CreateUser": "PW",
        "DeleteAccessKey": "PW",
        "DeleteRole": "PW",
        "GetPolicy": "R",
        "GetRole": "R",
        "GetUser": "R",
        "ListAttachedRolePolicies": "L",
        "ListRoles": "L",
        "ListUsers": "L",
        "PassRole": "W",
        "PutGroupPolicy": "PW",
        "PutRolePolicy": "PW",
        "PutUserPolicy": "PW",
        "SetDefaultPolicyVersion": "PW",
        "TagRole": "TW",
        "UpdateAssumeRolePolicy": "PW",
        "UpdateLoginProfile": "PW",
        "ChangePassword": "PW",
        "CreateServiceLinkedRole": "W",
    },
    "sts": {"AssumeRole": "W", "GetCallerIdentity": "R", "TagSession": "TW"},
    "s3": {
        "DeleteObject": "W",
        "GetBucketPolicy": "R",
        "GetObject": "R",
        "GetObjectTagging": "R",
        "ListAllMyBuckets": "L",
        "ListBucket": "L",
        "PutBucketPolicy": "PW",
        "PutObject": "W",
        "PutObjectAcl": "PW",
        "PutObjectTagging": "TW",
    },
    "ec2": {
        "CreateTags": "TW",
        "DescribeInstances": "L",
        "RunInstances": "W",
        "TerminateInstances": "W",
        "ModifyInstanceAttribute": "W",
        "StartInstances": "W",
        "StopInstances": "W",
    },
    "lambda": {
        "AddPermission": "PW",
        "CreateEventSourceMapping": "W",
        "CreateFunction": "W",
        "GetFunction": "R",
        "InvokeFunction": "W",
        "ListFunctions": "L",
        "UpdateFunctionCode": "W",
    },
    "kms": {"CreateGrant": "PW", "Decrypt": "W", "Encrypt": "W", "PutKeyPolicy": "PW", "RetireGrant": "PW"},
    "sqs": {"SendMessage": "W", "ReceiveMessage": "R", "SetQueueAttributes": "PW"},
    "secretsmanager": {"GetSecretValue": "R", "PutResourcePolicy": "PW"},
    "cloudformation": {"CreateStack": "W", "UpdateStack": "W", "DescribeStacks": "L"},
    "glue": {"CreateDevEndpoint": "W", "UpdateDevEndpoint": "W"},
    "ssm": {"SendCommand": "W", "StartSession": "W"},
}

_RESOURCES = {
    "iam": [
        ("role", "arn:${Partition}:iam::${Account}:role/${RoleNameWithPath}"),
        ("user", "arn:${Partition}:iam::${Account}:user/${UserNameWithPath}"),
        ("policy", "arn:${Partition}:iam::${Account}:policy/${PolicyNameWithPath}"),
    ],
    "s3": [
        ("bucket", "arn:${Partition}:s3:::${BucketName}"),
        ("object", "arn:${Partition}:s3:::${BucketName}/${ObjectName}"),
    ],
}


def raw_service(prefix: str) -> dict[str, Any]:
    actions = []
    for name, flags in sorted(SERVICES[prefix].items()):
        props = {
            "IsList": "L" in flags,
            "IsPermissionManagement": "P" in flags,
            "IsTaggingOnly": "T" in flags,
            "IsWrite": "W" in flags,
        }
        entry: dict[str, Any] = {"Name": name, "Annotations": {"Properties": props}}
        if prefix == "iam" and name == "PassRole":
            entry["ActionConditionKeys"] = ["iam:AssociatedResourceArn", "iam:PassedToService"]
            entry["Resources"] = [{"Name": "role"}]
        actions.append(entry)
    return {
        "Name": prefix,
        "ServiceName": prefix.upper(),
        "Actions": actions,
        "Resources": [{"Name": n, "ARNFormats": [f]} for n, f in _RESOURCES.get(prefix, [])],
        "ConditionKeys": [],
        "Version": "v1.5",
    }


BASE = "https://servicereference.us-east-1.amazonaws.com"


def fake_fetch(url: str) -> Any:
    if url == BASE + "/":
        return [{"service": s, "url": f"{BASE}/v1/{s}/{s}.json"} for s in sorted(SERVICES)]
    prefix = url.rsplit("/", 1)[1].removesuffix(".json")
    return raw_service(prefix)
