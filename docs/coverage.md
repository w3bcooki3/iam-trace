# Escalation coverage

<!-- Written by tests/benchmark/bench.py --write. Do not edit by hand. -->

iam-trace is benchmarked against every AWS path in
[pathfinding.cloud](https://pathfinding.cloud) (commit `043c20173d52`).
For each path the benchmark builds small accounts from pathfinding.cloud's own description of
it (the required permissions, and the service a passed role must trust), not from iam-trace's
tables, and runs the analysis. `tests/unit/test_benchmark.py` runs it on every change.

- **91 of 91** paths are confirmed (reported as a path to admin):
  68 from the IAM export alone, and 23 that act on an existing resource
  with a resource inventory. None is only possible. None is missed.
- **91 of 91** raise no false alarm in 1136 near misses: each required
  permission removed, denied by the identity policy, denied by an SCP, or left out of a
  permissions boundary; a target that is not admin; a passed role trusted by another
  service; PassRole limited to another service or another role; and, for existing
  resources, a Deny on that resource or a resource whose role is not admin.

"Existing resource" paths (a Lambda function, an EC2 instance, a CodeBuild project that
already runs as a role) are confirmed only with a resource inventory
(`iam-trace inventory collect`). Without one they are reported as possible, with every role
the service could be running as.

## What the benchmark does not show

- The accounts are small and each holds one path. Real accounts mix many; the engine's
  search across them is covered by the unit tests, not by this table.
- Paths that exist in AWS but not yet in pathfinding.cloud are not counted.
- The benchmark checks iam-trace against a description of AWS, not against AWS itself.
  A path that pathfinding.cloud describes wrongly would be scored wrongly too.
- See [limitations](limitations.md) for what the engine does not model.

## Every path

| Path | Permissions | Without inventory | With inventory | Near misses | False alarms |
|---|---|---|---|---|---|
| [apprunner-001](https://pathfinding.cloud/paths/apprunner-001) | iam:PassRole + apprunner:CreateService | Confirmed | not needed | 12 | none |
| [apprunner-002](https://pathfinding.cloud/paths/apprunner-002) | apprunner:UpdateService | Possible | Confirmed | 7 | none |
| [batch-001](https://pathfinding.cloud/paths/batch-001) | iam:PassRole + batch:RegisterJobDefinition + batch:SubmitJob | Confirmed | not needed | 16 | none |
| [batch-002](https://pathfinding.cloud/paths/batch-002) | batch:SubmitJob | Possible | Confirmed | 7 | none |
| [batch-003](https://pathfinding.cloud/paths/batch-003) | iam:PassRole + batch:CreateComputeEnvironment + batch:CreateJobQueue + batch:RegisterJobDefinition + batch:SubmitJob | Confirmed | not needed | 24 | none |
| [bedrock-001](https://pathfinding.cloud/paths/bedrock-001) | iam:PassRole + bedrock-agentcore:CreateCodeInterpreter + bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter | Confirmed | not needed | 20 | none |
| [bedrock-002](https://pathfinding.cloud/paths/bedrock-002) | bedrock-agentcore:StartCodeInterpreterSession + bedrock-agentcore:InvokeCodeInterpreter | Possible | Confirmed | 12 | none |
| [bedrock-003](https://pathfinding.cloud/paths/bedrock-003) | iam:PassRole + bedrock-agentcore:CreateAgentRuntime + bedrock-agentcore:CreateAgentRuntimeEndpoint + bedrock-agentcore:CreateWorkloadIdentity + bedrock-agentcore:InvokeAgentRuntimeCommand | Confirmed | not needed | 24 | none |
| [bedrock-004](https://pathfinding.cloud/paths/bedrock-004) | bedrock-agentcore:InvokeAgentRuntimeCommand | Possible | Confirmed | 7 | none |
| [bedrock-005](https://pathfinding.cloud/paths/bedrock-005) | iam:PassRole + bedrock-agentcore:CreateHarness + bedrock-agentcore:CreateAgentRuntime + bedrock-agentcore:CreateAgentRuntimeEndpoint + bedrock-agentcore:CreateWorkloadIdentity + bedrock-agentcore:GetAgentRuntime + bedrock-agentcore:GetHarness + bedrock-agentcore:InvokeAgentRuntimeCommand | Confirmed | not needed | 36 | none |
| [bedrock-006](https://pathfinding.cloud/paths/bedrock-006) | iam:PassRole + bedrock-agentcore:CreateBrowser + bedrock-agentcore:StartBrowserSession + bedrock-agentcore:ConnectBrowserAutomationStream | Confirmed | not needed | 20 | none |
| [bedrock-007](https://pathfinding.cloud/paths/bedrock-007) | bedrock-agentcore:StartBrowserSession + bedrock-agentcore:ConnectBrowserAutomationStream | Possible | Confirmed | 12 | none |
| [braket-001](https://pathfinding.cloud/paths/braket-001) | iam:PassRole + braket:CreateJob | Confirmed | not needed | 12 | none |
| [cloudformation-001](https://pathfinding.cloud/paths/cloudformation-001) | iam:PassRole + cloudformation:CreateStack | Confirmed | not needed | 12 | none |
| [cloudformation-002](https://pathfinding.cloud/paths/cloudformation-002) | cloudformation:UpdateStack | Possible | Confirmed | 7 | none |
| [cloudformation-003](https://pathfinding.cloud/paths/cloudformation-003) | iam:PassRole + cloudformation:CreateStackSet + cloudformation:CreateStackInstances | Confirmed | not needed | 16 | none |
| [cloudformation-004](https://pathfinding.cloud/paths/cloudformation-004) | iam:PassRole + cloudformation:UpdateStackSet | Confirmed | not needed | 12 | none |
| [cloudformation-005](https://pathfinding.cloud/paths/cloudformation-005) | cloudformation:CreateChangeSet + cloudformation:ExecuteChangeSet | Possible | Confirmed | 13 | none |
| [codebuild-001](https://pathfinding.cloud/paths/codebuild-001) | iam:PassRole + codebuild:CreateProject + codebuild:StartBuild | Confirmed | not needed | 16 | none |
| [codebuild-002](https://pathfinding.cloud/paths/codebuild-002) | codebuild:StartBuild | Possible | Confirmed | 7 | none |
| [codebuild-003](https://pathfinding.cloud/paths/codebuild-003) | codebuild:StartBuildBatch | Possible | Confirmed | 7 | none |
| [codebuild-004](https://pathfinding.cloud/paths/codebuild-004) | iam:PassRole + codebuild:CreateProject + codebuild:StartBuildBatch | Confirmed | not needed | 16 | none |
| [codedeploy-001](https://pathfinding.cloud/paths/codedeploy-001) | codedeploy:CreateDeployment | Possible | Confirmed | 17 | none |
| [cognitoidentity-001](https://pathfinding.cloud/paths/cognitoidentity-001) | iam:PassRole + cognito-identity:SetIdentityPoolRoles | Confirmed | not needed | 12 | none |
| [datapipeline-001](https://pathfinding.cloud/paths/datapipeline-001) | iam:PassRole + datapipeline:CreatePipeline + datapipeline:PutPipelineDefinition + datapipeline:ActivatePipeline | Confirmed | not needed | 20 | none |
| [ec2-001](https://pathfinding.cloud/paths/ec2-001) | iam:PassRole + ec2:RunInstances | Confirmed | not needed | 12 | none |
| [ec2-002](https://pathfinding.cloud/paths/ec2-002) | ec2:ModifyInstanceAttribute + ec2:StopInstances + ec2:StartInstances | Possible | Confirmed | 17 | none |
| [ec2-003](https://pathfinding.cloud/paths/ec2-003) | iam:PassRole + ec2:RequestSpotInstances | Confirmed | not needed | 12 | none |
| [ec2-005](https://pathfinding.cloud/paths/ec2-005) | ec2:CreateLaunchTemplateVersion + ec2:ModifyLaunchTemplate | Possible | Confirmed | 12 | none |
| [ec2instanceconnect-003](https://pathfinding.cloud/paths/ec2instanceconnect-003) | ec2-instance-connect:SendSSHPublicKey | Possible | Confirmed | 12 | none |
| [ecs-001](https://pathfinding.cloud/paths/ecs-001) | iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:CreateService | Confirmed | not needed | 20 | none |
| [ecs-002](https://pathfinding.cloud/paths/ecs-002) | iam:PassRole + ecs:CreateCluster + ecs:RegisterTaskDefinition + ecs:RunTask | Confirmed | not needed | 20 | none |
| [ecs-003](https://pathfinding.cloud/paths/ecs-003) | iam:PassRole + ecs:RegisterTaskDefinition + ecs:CreateService | Confirmed | not needed | 16 | none |
| [ecs-004](https://pathfinding.cloud/paths/ecs-004) | iam:PassRole + ecs:RegisterTaskDefinition + ecs:RunTask | Confirmed | not needed | 16 | none |
| [ecs-005](https://pathfinding.cloud/paths/ecs-005) | iam:PassRole + ecs:RegisterTaskDefinition + ecs:StartTask | Confirmed | not needed | 16 | none |
| [ecs-006](https://pathfinding.cloud/paths/ecs-006) | ecs:ExecuteCommand + ecs:DescribeTasks | Possible | Confirmed | 12 | none |
| [ecs-007](https://pathfinding.cloud/paths/ecs-007) | iam:PassRole + ecs:StartTask + ecs:RegisterContainerInstance | Confirmed | not needed | 16 | none |
| [ecs-008](https://pathfinding.cloud/paths/ecs-008) | iam:PassRole + ecs:RunTask | Confirmed | not needed | 12 | none |
| [ecs-009](https://pathfinding.cloud/paths/ecs-009) | iam:PassRole + ecs:StartTask | Confirmed | not needed | 12 | none |
| [emr-001](https://pathfinding.cloud/paths/emr-001) | iam:PassRole + elasticmapreduce:RunJobFlow | Confirmed | not needed | 12 | none |
| [emrserverless-001](https://pathfinding.cloud/paths/emrserverless-001) | iam:PassRole + emr-serverless:CreateApplication + emr-serverless:StartJobRun | Confirmed | not needed | 16 | none |
| [gamelift-001](https://pathfinding.cloud/paths/gamelift-001) | iam:PassRole + gamelift:CreateBuild + gamelift:CreateFleet | Confirmed | not needed | 20 | none |
| [glue-001](https://pathfinding.cloud/paths/glue-001) | iam:PassRole + glue:CreateDevEndpoint | Confirmed | not needed | 12 | none |
| [glue-002](https://pathfinding.cloud/paths/glue-002) | glue:UpdateDevEndpoint | Possible | Confirmed | 7 | none |
| [glue-003](https://pathfinding.cloud/paths/glue-003) | iam:PassRole + glue:CreateJob + glue:StartJobRun | Confirmed | not needed | 16 | none |
| [glue-004](https://pathfinding.cloud/paths/glue-004) | iam:PassRole + glue:CreateJob + glue:CreateTrigger | Confirmed | not needed | 16 | none |
| [glue-005](https://pathfinding.cloud/paths/glue-005) | iam:PassRole + glue:UpdateJob + glue:StartJobRun | Confirmed | not needed | 16 | none |
| [glue-006](https://pathfinding.cloud/paths/glue-006) | iam:PassRole + glue:UpdateJob + glue:CreateTrigger | Confirmed | not needed | 16 | none |
| [glue-007](https://pathfinding.cloud/paths/glue-007) | iam:PassRole + glue:CreateSession + glue:RunStatement | Confirmed | not needed | 16 | none |
| [iam-001](https://pathfinding.cloud/paths/iam-001) | iam:CreatePolicyVersion | Confirmed | not needed | 5 | none |
| [iam-002](https://pathfinding.cloud/paths/iam-002) | iam:CreateAccessKey | Confirmed | not needed | 5 | none |
| [iam-003](https://pathfinding.cloud/paths/iam-003) | iam:CreateAccessKey + iam:DeleteAccessKey | Confirmed | not needed | 9 | none |
| [iam-004](https://pathfinding.cloud/paths/iam-004) | iam:CreateLoginProfile | Confirmed | not needed | 5 | none |
| [iam-005](https://pathfinding.cloud/paths/iam-005) | iam:PutRolePolicy | Confirmed | not needed | 5 | none |
| [iam-006](https://pathfinding.cloud/paths/iam-006) | iam:UpdateLoginProfile | Confirmed | not needed | 5 | none |
| [iam-007](https://pathfinding.cloud/paths/iam-007) | iam:PutUserPolicy | Confirmed | not needed | 5 | none |
| [iam-008](https://pathfinding.cloud/paths/iam-008) | iam:AttachUserPolicy | Confirmed | not needed | 5 | none |
| [iam-009](https://pathfinding.cloud/paths/iam-009) | iam:AttachRolePolicy | Confirmed | not needed | 5 | none |
| [iam-010](https://pathfinding.cloud/paths/iam-010) | iam:AttachGroupPolicy | Confirmed | not needed | 5 | none |
| [iam-011](https://pathfinding.cloud/paths/iam-011) | iam:PutGroupPolicy | Confirmed | not needed | 5 | none |
| [iam-012](https://pathfinding.cloud/paths/iam-012) | iam:UpdateAssumeRolePolicy | Confirmed | not needed | 5 | none |
| [iam-013](https://pathfinding.cloud/paths/iam-013) | iam:AddUserToGroup | Confirmed | not needed | 5 | none |
| [iam-014](https://pathfinding.cloud/paths/iam-014) | iam:AttachRolePolicy + sts:AssumeRole | Confirmed | not needed | 9 | none |
| [iam-015](https://pathfinding.cloud/paths/iam-015) | iam:AttachUserPolicy + iam:CreateAccessKey | Confirmed | not needed | 9 | none |
| [iam-016](https://pathfinding.cloud/paths/iam-016) | iam:CreatePolicyVersion + sts:AssumeRole | Confirmed | not needed | 9 | none |
| [iam-017](https://pathfinding.cloud/paths/iam-017) | iam:PutRolePolicy + sts:AssumeRole | Confirmed | not needed | 9 | none |
| [iam-018](https://pathfinding.cloud/paths/iam-018) | iam:PutUserPolicy + iam:CreateAccessKey | Confirmed | not needed | 9 | none |
| [iam-019](https://pathfinding.cloud/paths/iam-019) | iam:AttachRolePolicy + iam:UpdateAssumeRolePolicy | Confirmed | not needed | 9 | none |
| [iam-020](https://pathfinding.cloud/paths/iam-020) | iam:CreatePolicyVersion + iam:UpdateAssumeRolePolicy | Confirmed | not needed | 9 | none |
| [iam-021](https://pathfinding.cloud/paths/iam-021) | iam:PutRolePolicy + iam:UpdateAssumeRolePolicy | Confirmed | not needed | 9 | none |
| [imagebuilder-001](https://pathfinding.cloud/paths/imagebuilder-001) | iam:PassRole + imagebuilder:CreateComponent + imagebuilder:CreateImageRecipe + imagebuilder:CreateInfrastructureConfiguration + imagebuilder:CreateImage | Confirmed | not needed | 24 | none |
| [kinesisanalytics-001](https://pathfinding.cloud/paths/kinesisanalytics-001) | iam:PassRole + kinesisanalytics:CreateApplication + kinesisanalytics:StartApplication | Confirmed | not needed | 16 | none |
| [lambda-001](https://pathfinding.cloud/paths/lambda-001) | iam:PassRole + lambda:CreateFunction + lambda:InvokeFunction | Confirmed | not needed | 16 | none |
| [lambda-002](https://pathfinding.cloud/paths/lambda-002) | iam:PassRole + lambda:CreateFunction + lambda:CreateEventSourceMapping | Confirmed | not needed | 16 | none |
| [lambda-003](https://pathfinding.cloud/paths/lambda-003) | lambda:UpdateFunctionCode | Possible | Confirmed | 7 | none |
| [lambda-004](https://pathfinding.cloud/paths/lambda-004) | lambda:UpdateFunctionCode + lambda:InvokeFunction | Possible | Confirmed | 12 | none |
| [lambda-005](https://pathfinding.cloud/paths/lambda-005) | lambda:UpdateFunctionCode + lambda:AddPermission | Possible | Confirmed | 12 | none |
| [lambda-006](https://pathfinding.cloud/paths/lambda-006) | iam:PassRole + lambda:CreateFunction + lambda:AddPermission | Confirmed | not needed | 16 | none |
| [omics-001](https://pathfinding.cloud/paths/omics-001) | iam:PassRole + omics:CreateWorkflow + omics:StartRun | Confirmed | not needed | 20 | none |
| [sagemaker-001](https://pathfinding.cloud/paths/sagemaker-001) | iam:PassRole + sagemaker:CreateNotebookInstance | Confirmed | not needed | 12 | none |
| [sagemaker-002](https://pathfinding.cloud/paths/sagemaker-002) | iam:PassRole + sagemaker:CreateTrainingJob | Confirmed | not needed | 12 | none |
| [sagemaker-003](https://pathfinding.cloud/paths/sagemaker-003) | iam:PassRole + sagemaker:CreateProcessingJob | Confirmed | not needed | 12 | none |
| [sagemaker-004](https://pathfinding.cloud/paths/sagemaker-004) | sagemaker:CreatePresignedNotebookInstanceUrl | Possible | Confirmed | 7 | none |
| [sagemaker-005](https://pathfinding.cloud/paths/sagemaker-005) | sagemaker:CreateNotebookInstanceLifecycleConfig + sagemaker:StopNotebookInstance + sagemaker:UpdateNotebookInstance + sagemaker:StartNotebookInstance | Possible | Confirmed | 22 | none |
| [scheduler-001](https://pathfinding.cloud/paths/scheduler-001) | iam:PassRole + scheduler:CreateSchedule | Confirmed | not needed | 12 | none |
| [ssm-001](https://pathfinding.cloud/paths/ssm-001) | ssm:StartSession | Possible | Confirmed | 7 | none |
| [ssm-002](https://pathfinding.cloud/paths/ssm-002) | ssm:SendCommand | Possible | Confirmed | 7 | none |
| [ssm-003](https://pathfinding.cloud/paths/ssm-003) | iam:PassRole + ssm:CreateDocument + ssm:StartAutomationExecution | Confirmed | not needed | 16 | none |
| [stepfunctions-001](https://pathfinding.cloud/paths/stepfunctions-001) | iam:PassRole + states:CreateStateMachine + states:StartExecution | Confirmed | not needed | 16 | none |
| [stepfunctions-002](https://pathfinding.cloud/paths/stepfunctions-002) | states:UpdateStateMachine + states:StartExecution | Possible | Confirmed | 12 | none |
| [sts-001](https://pathfinding.cloud/paths/sts-001) | sts:AssumeRole | Confirmed | not needed | 5 | none |

pathfinding.cloud is Apache-2.0, Copyright 2025-Present Datadog, Inc.
