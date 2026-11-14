// Ready-made scenarios for the page. Each one shows a different rule of AWS's evaluation logic.

const V = "2012-10-17";
const A = "111122223333";
const B = "444455556666";

export const EVALUATE_EXAMPLES = [
  {
    title: "Read from your own bucket",
    principal: `arn:aws:iam::${A}:user/alice`,
    action: "s3:GetObject",
    resource: "arn:aws:s3:::example-app/reports/2026-q3.csv",
    account: A,
    context: "aws:SecureTransport=true",
    policies: {
      identity: {
        Version: V,
        Statement: [{ Sid: "ReadAppBucket", Effect: "Allow", Action: ["s3:GetObject", "s3:ListBucket"],
          Resource: ["arn:aws:s3:::example-app", "arn:aws:s3:::example-app/*"] }],
      },
      resource_policy: {
        Version: V,
        Statement: [{ Sid: "TLSOnly", Effect: "Deny", Principal: "*", Action: "s3:*",
          Resource: ["arn:aws:s3:::example-app", "arn:aws:s3:::example-app/*"],
          Condition: { Bool: { "aws:SecureTransport": "false" } } }],
      },
    },
  },
  {
    title: "Cross-account role reads a partner bucket",
    principal: `arn:aws:sts::${A}:assumed-role/analytics/etl-run`,
    action: "s3:GetObject",
    resource: "arn:aws:s3:::partner-data/exports/orders.parquet",
    account: B,
    context: "",
    policies: {
      identity: {
        Version: V,
        Statement: [{ Sid: "ReadPartnerExports", Effect: "Allow", Action: "s3:GetObject",
          Resource: "arn:aws:s3:::partner-data/exports/*" }],
      },
      resource_policy: {
        Version: V,
        Statement: [{ Sid: "AnalyticsRole", Effect: "Allow", Principal: { AWS: `arn:aws:iam::${A}:role/analytics` },
          Action: "s3:GetObject", Resource: "arn:aws:s3:::partner-data/exports/*" }],
      },
    },
  },
  {
    title: "A permissions boundary blocks user creation",
    principal: `arn:aws:iam::${A}:user/team-lead`,
    action: "iam:CreateUser",
    resource: `arn:aws:iam::${A}:user/new-hire`,
    account: A,
    context: "",
    policies: {
      identity: { Version: V, Statement: [{ Sid: "IAMAdmin", Effect: "Allow", Action: "iam:*", Resource: "*" }] },
      boundary: {
        Version: V,
        Statement: [{ Sid: "WorkloadServicesOnly", Effect: "Allow", Action: ["s3:*", "ec2:*", "cloudwatch:*"], Resource: "*" }],
      },
    },
  },
  {
    title: "An SCP denies an unapproved region",
    principal: `arn:aws:iam::${A}:user/alice`,
    action: "ec2:RunInstances",
    resource: "*",
    account: A,
    context: "aws:RequestedRegion=ap-south-1",
    policies: {
      identity: { Version: V, Statement: [{ Effect: "Allow", Action: "ec2:*", Resource: "*" }] },
      scp: {
        Version: V,
        Statement: [
          { Sid: "AllowAll", Effect: "Allow", Action: "*", Resource: "*" },
          { Sid: "ApprovedRegionsOnly", Effect: "Deny", NotAction: ["iam:*", "sts:*", "organizations:*"], Resource: "*",
            Condition: { StringNotEquals: { "aws:RequestedRegion": ["us-east-1", "eu-west-1"] } } },
        ],
      },
    },
  },
  {
    title: "A grant to the session ARN gets past the boundary",
    principal: `arn:aws:sts::${A}:assumed-role/app/worker-7`,
    action: "secretsmanager:GetSecretValue",
    resource: `arn:aws:secretsmanager:us-east-1:${A}:secret:db-password-Ab12Cd`,
    account: A,
    context: "",
    policies: {
      resource_policy: {
        Version: V,
        Statement: [{ Sid: "OneSession", Effect: "Allow", Principal: { AWS: `arn:aws:sts::${A}:assumed-role/app/worker-7` },
          Action: "secretsmanager:GetSecretValue", Resource: "*" }],
      },
      boundary: { Version: V, Statement: [{ Effect: "Allow", Action: "s3:*", Resource: "*" }] },
    },
  },
];

export const DIFF_EXAMPLE = {
  before: {
    Version: V,
    Statement: [
      { Sid: "ReadReports", Effect: "Allow", Action: ["s3:GetObject", "s3:ListBucket"],
        Resource: ["arn:aws:s3:::example-app", "arn:aws:s3:::example-app/reports/*"] },
      { Sid: "DeployFunctions", Effect: "Allow", Action: "lambda:UpdateFunctionCode",
        Resource: `arn:aws:lambda:us-east-1:${A}:function:app-*`,
        Condition: { Bool: { "aws:MultiFactorAuthPresent": "true" } } },
    ],
  },
  after: {
    Version: V,
    Statement: [
      { Sid: "DeployFunctions", Effect: "Allow", Action: ["lambda:UpdateFunctionCode", "lambda:CreateFunction"],
        Resource: `arn:aws:lambda:us-east-1:${A}:function:app-*` },
      { Sid: "PassExecutionRole", Effect: "Allow", Action: "iam:PassRole", Resource: "*" },
      { Sid: "ReadAndWriteApp", Effect: "Allow", Action: ["s3:ListBucket", "s3:GetObject", "s3:PutObject"],
        Resource: ["arn:aws:s3:::example-app", "arn:aws:s3:::example-app/*"] },
    ],
  },
};

export const ATTACK_POLICY_EXAMPLE = {
  Version: V,
  Statement: [
    { Sid: "Deploy", Effect: "Allow",
      Action: ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction", "ec2:RunInstances"], Resource: "*" },
    { Sid: "ManageKeys", Effect: "Allow", Action: ["iam:CreateAccessKey", "iam:ListUsers"], Resource: "*" },
  ],
};
