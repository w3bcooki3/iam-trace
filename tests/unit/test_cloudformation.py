"""CloudFormation templates: the YAML reader, intrinsic functions, and the review built on the Terraform one."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from iamtrace.catalog import default_catalog
from iamtrace.cfnyaml import YamlError, loads
from iamtrace.cli import main
from iamtrace.cloudformation import TemplateError, review, to_plan
from iamtrace.terraform import review_markdown, review_text
from iamtrace.web_api import change_query

ROOT = Path(__file__).resolve().parents[2]
CAT = default_catalog()
SAMPLE = ROOT / "examples" / "sample"

TEMPLATE = """\
AWSTemplateFormatVersion: "2010-09-09"
Description: >
  Build pipeline: a role CodeBuild runs as,
  and the policy it deploys with.
Parameters:
  Env:
    Type: String
    Default: prod   # the stage
    AllowedValues: [dev, prod]
Conditions:
  IsProd: !Equals [!Ref Env, prod]
  NotProd: !Not [!Condition IsProd]
Mappings:
  Buckets:
    prod: {Name: artefacts-prod}
    dev: {Name: artefacts-dev}
Resources:
  BuildRole:
    Type: AWS::IAM::Role
    Properties:
      RoleName: !Sub "${Env}-build"
      AssumeRolePolicyDocument:
        Version: 2012-10-17
        Statement:
          - Effect: Allow
            Principal: { Service: codebuild.amazonaws.com }
            Action: sts:AssumeRole
      Policies:
        - PolicyName: deploy
          PolicyDocument:
            Version: '2012-10-17'
            Statement:
              - Effect: Allow
                Action:
                  - iam:PassRole
                  - lambda:CreateFunction
                  - lambda:InvokeFunction
                Resource: "*"
              - !If
                - IsProd
                - Effect: Allow
                  Action: s3:GetObject
                  Resource: !Sub
                    - "arn:${AWS::Partition}:s3:::${B}/*"
                    - B: !FindInMap [Buckets, !Ref Env, Name]
                - !Ref AWS::NoValue
  DebugUser:
    Type: AWS::IAM::User
    Condition: NotProd
    Properties:
      Policies:
        - PolicyName: all
          PolicyDocument: {Version: "2012-10-17", Statement: [{Effect: Allow, Action: "*", Resource: "*"}]}
  Ops:
    Type: AWS::IAM::ManagedPolicy
    Properties:
      ManagedPolicyName: ops
      Roles: [!Ref BuildRole]
      PolicyDocument:
        Version: "2012-10-17"
        Statement:
          - Effect: Allow
            Action: iam:AttachRolePolicy
            Resource: !GetAtt BuildRole.Arn
  Script:
    Type: AWS::SSM::Parameter
    Properties:
      Type: String
      Value: |
        line one
          indented
        line three
      Description: 'it''s kept'
"""


def test_reads_the_yaml_templates_use_as_pyyaml_would() -> None:
    yaml = pytest.importorskip("yaml")

    class Loader(yaml.SafeLoader):  # CloudFormation's short tags as their long forms, dates kept as text
        pass

    def tag(name: str) -> Any:
        long = name if name in ("Ref", "Condition") else f"Fn::{name}"

        def build(loader: Any, node: Any) -> Any:
            if isinstance(node, yaml.ScalarNode):
                v: Any = loader.construct_scalar(node)
                if name == "GetAtt":
                    v = v.split(".", 1)
            elif isinstance(node, yaml.SequenceNode):
                v = loader.construct_sequence(node, deep=True)
            else:
                v = loader.construct_mapping(node, deep=True)
            return {long: v}

        return build

    for t in (
        "Ref",
        "Condition",
        "Sub",
        "GetAtt",
        "Join",
        "If",
        "Select",
        "Split",
        "FindInMap",
        "ImportValue",
        "Equals",
        "Not",
        "And",
        "Or",
    ):
        Loader.add_constructor(f"!{t}", tag(t))
    Loader.yaml_implicit_resolvers = {
        k: [r for r in v if r[0] != "tag:yaml.org,2002:timestamp"] for k, v in Loader.yaml_implicit_resolvers.items()
    }
    assert loads(TEMPLATE) == yaml.load(TEMPLATE, Loader=Loader)  # noqa: S506 - a SafeLoader subclass


def test_yaml_edges() -> None:
    assert loads("a: 'x: y'\nb: \"tab\\tthere\"\nc: [1, 'two', {d: e}]\nd: ~\n") == {
        "a": "x: y",
        "b": "tab\tthere",
        "c": [1, "two", {"d": "e"}],
        "d": None,
    }
    assert loads("k: >-\n  one\n  two\n\n  three\nn: 1\n") == {"k": "one two\nthree", "n": 1}
    assert loads("- a\n- - b\n  - c\n-\n  x: 1\n") == ["a", ["b", "c"], {"x": 1}]
    assert loads("v: !GetAtt [R, Arn]\nw: !Join\n  - ''\n  - [a, !Ref B]\n") == {
        "v": {"Fn::GetAtt": ["R", "Arn"]},
        "w": {"Fn::Join": ["", ["a", {"Ref": "B"}]]},
    }
    assert loads('{"Resources": {}}') == {"Resources": {}}
    assert loads("a: 'it''s # not a comment' # comment\nb: \"x\\\" # y\" # c\n") == {
        "a": "it's # not a comment",
        "b": 'x" # y',
    }
    for bad, why in (
        ("a: &x 1\nb: *x\n", "anchors"),
        ("a: 1\na: 2\n", "twice"),
        ("a: !Foo x\n", "!Foo"),
        ("a:\n\tb: 1\n", "tabs"),
        ("a: [1, 2\n", "never closed"),
    ):
        with pytest.raises(YamlError, match=why):
            loads(bad)


def test_resolves_intrinsics_and_conditions() -> None:
    plan, notes = to_plan(TEMPLATE, stack="pipe")
    by = {c["address"]: c for c in plan["resource_changes"]}
    role = by["BuildRole"]["change"]["after"]
    assert role["name"] == "prod-build"
    stmts = json.loads(role["inline_policy"][0]["policy"])["Statement"]
    assert stmts[1]["Resource"] == "arn:aws:s3:::artefacts-prod/*"  # Fn::If true branch, Fn::Sub with a map, FindInMap
    assert "DebugUser" not in by and not any(a.startswith("DebugUser") for a in by)  # its Condition is false
    pol = by["Ops"]["change"]["after"]
    assert pol["arn"] == "arn:aws:iam::111122223333:policy/ops"
    assert json.loads(pol["policy"])["Statement"][0]["Resource"] == "arn:aws:iam::111122223333:role/prod-build"
    assert by["Ops.Roles.prod-build"]["type"] == "aws_iam_role_policy_attachment"
    assert notes == []
    # another parameter value turns the other branch and the debug user on
    plan, _ = to_plan(TEMPLATE, params={"Env": "dev"}, stack="pipe")
    by = {c["address"]: c for c in plan["resource_changes"]}
    assert len(json.loads(by["BuildRole"]["change"]["after"]["inline_policy"][0]["policy"])["Statement"]) == 1
    assert by["DebugUser"]["change"]["after"]["name"] == "pipe-DebugUser"
    assert by["DebugUser.Policies.all"]["type"] == "aws_iam_user_policy"


def test_what_is_not_known_before_deployment_is_a_visible_placeholder() -> None:
    tpl = {
        "Parameters": {"Team": {"Type": "String"}},
        "Resources": {
            "P": {
                "Type": "AWS::IAM::ManagedPolicy",
                "Properties": {
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Action": "s3:*",
                                "Resource": {
                                    "Fn::Sub": [
                                        "${Shared}/${Team}/*",
                                        {"Shared": {"Fn::ImportValue": "SharedBucketArn"}},
                                    ]
                                },
                            }
                        ],
                    }
                },
            }
        },
    }
    plan, notes = to_plan(json.dumps(tpl))
    doc = json.loads(plan["resource_changes"][0]["change"]["after"]["policy"])
    assert doc["Statement"][0]["Resource"] == "${Import:SharedBucketArn}/${Team}/*"
    assert any("Team has no value" in n for n in notes) and any("ImportValue SharedBucketArn" in n for n in notes)


def test_review_finds_the_escalation_and_with_the_account_the_new_admin() -> None:
    r = review(TEMPLATE, CAT)
    assert r["source"] == "cloudformation"
    assert {t["id"] for d in r["documents"] for t in d["new_escalations"]} == {"lambda-001"}
    assert any(f["rule"] == "passrole-any-role" for d in r["documents"] for f in d["new_checks"])
    export = json.loads((SAMPLE / "auth-details.json").read_text())
    r = review(TEMPLATE, CAT, export=export)
    assert (
        "arn:aws:iam::" + export["RoleDetailList"][0]["Arn"].split(":")[4] + ":role/prod-build"
        in r["account"]["new_admins"]
    )
    text, md = review_text(r), review_markdown(r)
    assert text.startswith("CloudFormation template:") and "NEW ADMIN role/prod-build" in text
    assert "<!-- iam-trace-cloudformation -->" in md and "This template opens a path to admin" in md


def test_previous_template_reviews_only_the_change() -> None:
    before = TEMPLATE.replace("                  - lambda:InvokeFunction\n", "")
    r = review(TEMPLATE, CAT, before_text=before)
    docs = {(d["address"], d["kind"]): d for d in r["documents"]}
    assert set(docs) == {("BuildRole", "inline")}  # the trust policy and Ops did not change
    assert docs[("BuildRole", "inline")]["action"] == "update"
    assert [t["id"] for t in docs[("BuildRole", "inline")]["new_escalations"]] == ["lambda-001"]
    assert review(TEMPLATE, CAT, before_text=TEMPLATE)["documents"] == []
    # a renamed role is replaced: deleted, then created
    plan, _ = to_plan(TEMPLATE.replace('!Sub "${Env}-build"', "builder"), TEMPLATE)
    assert [c["change"]["actions"] for c in plan["resource_changes"] if c["address"] == "BuildRole"] == [
        ["delete", "create"]
    ]


def test_loops_and_deep_nesting_end_with_an_answer() -> None:
    loop = {
        "Conditions": {"A": {"Condition": "B"}, "B": {"Condition": "A"}},
        "Resources": {
            "R": {"Type": "AWS::IAM::Role", "Condition": "A", "Properties": {"RoleName": {"Fn::Sub": "${R.Arn}"}}}
        },
    }
    assert to_plan(json.dumps(loop))[0]["resource_changes"][0]["type"] == "aws_iam_role"
    deep: Any = {"Ref": "AWS::Region"}
    for _ in range(300):
        deep = {"Fn::Base64": deep}
    with pytest.raises(TemplateError, match="nested too deeply"):
        to_plan(
            json.dumps(
                {"Resources": {"P": {"Type": "AWS::IAM::ManagedPolicy", "Properties": {"PolicyDocument": deep}}}}
            )
        )
    with pytest.raises(YamlError, match="never closed|closed with|expected"):
        loads("Mappings:\n    prod: {Name: artefacts-ondition IsProd]\n")


def test_refuses_what_it_cannot_review() -> None:
    with pytest.raises(TemplateError, match="no Resources"):
        review("Description: nothing\n", CAT)
    with pytest.raises(TemplateError, match="SAM template"):
        review("Transform: AWS::Serverless-2016-10-31\nResources: {}\n", CAT)
    with pytest.raises(TemplateError, match="line 2"):
        review("Resources:\n  A: [1\n", CAT)


def test_cli_and_web(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    t = tmp_path / "t.yaml"
    t.write_text(TEMPLATE)
    assert main(["cloudformation", str(t), "--fail-on", "escalation"]) == 1
    assert "lambda-001" in capsys.readouterr().out
    assert main(["cfn", str(t), "--parameter", "Env=dev", "--format", "json"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert any(d["address"] == "DebugUser.Policies.all" for d in out["documents"])
    assert main(["cfn", str(t), "--parameter", "nope"]) == 2
    assert "Name=Value" in capsys.readouterr().err
    w = json.loads(change_query(TEMPLATE, ""))
    assert w["source"] == "cloudformation" and "iam-trace-cloudformation" in w["markdown"]
    tf = json.loads(change_query((SAMPLE / "terraform-plan.json").read_text(), ""))
    assert tf.get("source") != "cloudformation" and "iam-trace-terraform" in tf["markdown"]
    assert "not a Terraform plan" in json.loads(change_query('{"x": 1}', ""))["error"]
