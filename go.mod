module github.com/aws-samples/cryptamap

go 1.26.2

require (
	github.com/aws/aws-cdk-go/awscdk/v2 v2.257.0
	github.com/aws/aws-lambda-go v1.54.0
	github.com/aws/aws-sdk-go-v2 v1.42.0
	github.com/aws/aws-sdk-go-v2/config v1.32.20
	github.com/aws/aws-sdk-go-v2/credentials v1.19.19
	github.com/aws/aws-sdk-go-v2/service/acm v1.39.2
	github.com/aws/aws-sdk-go-v2/service/acmpca v1.47.2
	github.com/aws/aws-sdk-go-v2/service/apigateway v1.40.2
	github.com/aws/aws-sdk-go-v2/service/apigatewayv2 v1.35.2
	github.com/aws/aws-sdk-go-v2/service/appmesh v1.36.4
	github.com/aws/aws-sdk-go-v2/service/appsync v1.54.0
	github.com/aws/aws-sdk-go-v2/service/athena v1.58.4
	github.com/aws/aws-sdk-go-v2/service/backup v1.57.2
	github.com/aws/aws-sdk-go-v2/service/bedrock v1.64.0
	github.com/aws/aws-sdk-go-v2/service/bedrockagent v1.54.6
	github.com/aws/aws-sdk-go-v2/service/cloudfront v1.64.2
	github.com/aws/aws-sdk-go-v2/service/cloudhsmv2 v1.35.0
	github.com/aws/aws-sdk-go-v2/service/cloudtrail v1.56.2
	github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs v1.74.2
	github.com/aws/aws-sdk-go-v2/service/codebuild v1.69.4
	github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider v1.61.4
	github.com/aws/aws-sdk-go-v2/service/customerprofiles v1.62.5
	github.com/aws/aws-sdk-go-v2/service/databasemigrationservice v1.64.0
	github.com/aws/aws-sdk-go-v2/service/dax v1.30.2
	github.com/aws/aws-sdk-go-v2/service/directconnect v1.38.19
	github.com/aws/aws-sdk-go-v2/service/directoryservice v1.39.4
	github.com/aws/aws-sdk-go-v2/service/docdb v1.49.0
	github.com/aws/aws-sdk-go-v2/service/docdbelastic v1.21.7
	github.com/aws/aws-sdk-go-v2/service/dynamodb v1.57.6
	github.com/aws/aws-sdk-go-v2/service/ec2 v1.304.2
	github.com/aws/aws-sdk-go-v2/service/ecr v1.58.0
	github.com/aws/aws-sdk-go-v2/service/ecs v1.82.0
	github.com/aws/aws-sdk-go-v2/service/efs v1.41.18
	github.com/aws/aws-sdk-go-v2/service/eks v1.84.2
	github.com/aws/aws-sdk-go-v2/service/elasticache v1.53.0
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing v1.34.6
	github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2 v1.55.0
	github.com/aws/aws-sdk-go-v2/service/emr v1.61.1
	github.com/aws/aws-sdk-go-v2/service/emrserverless v1.42.2
	github.com/aws/aws-sdk-go-v2/service/eventbridge v1.46.6
	github.com/aws/aws-sdk-go-v2/service/firehose v1.43.2
	github.com/aws/aws-sdk-go-v2/service/fsx v1.66.2
	github.com/aws/aws-sdk-go-v2/service/globalaccelerator v1.36.2
	github.com/aws/aws-sdk-go-v2/service/glue v1.142.2
	github.com/aws/aws-sdk-go-v2/service/iam v1.54.0
	github.com/aws/aws-sdk-go-v2/service/iot v1.75.0
	github.com/aws/aws-sdk-go-v2/service/kafka v1.52.2
	github.com/aws/aws-sdk-go-v2/service/kendra v1.61.3
	github.com/aws/aws-sdk-go-v2/service/keyspaces v1.26.1
	github.com/aws/aws-sdk-go-v2/service/kinesis v1.43.9
	github.com/aws/aws-sdk-go-v2/service/kinesisanalyticsv2 v1.38.6
	github.com/aws/aws-sdk-go-v2/service/kms v1.53.0
	github.com/aws/aws-sdk-go-v2/service/lambda v1.91.0
	github.com/aws/aws-sdk-go-v2/service/lightsail v1.55.0
	github.com/aws/aws-sdk-go-v2/service/memorydb v1.34.2
	github.com/aws/aws-sdk-go-v2/service/mgn v1.45.0
	github.com/aws/aws-sdk-go-v2/service/mq v1.35.2
	github.com/aws/aws-sdk-go-v2/service/neptune v1.44.7
	github.com/aws/aws-sdk-go-v2/service/opensearch v1.70.2
	github.com/aws/aws-sdk-go-v2/service/opensearchserverless v1.32.1
	github.com/aws/aws-sdk-go-v2/service/organizations v1.51.6
	github.com/aws/aws-sdk-go-v2/service/paymentcryptography v1.31.1
	github.com/aws/aws-sdk-go-v2/service/qldb v1.32.2
	github.com/aws/aws-sdk-go-v2/service/quicksight v1.114.1
	github.com/aws/aws-sdk-go-v2/service/rds v1.118.4
	github.com/aws/aws-sdk-go-v2/service/redshift v1.62.10
	github.com/aws/aws-sdk-go-v2/service/redshiftserverless v1.35.8
	github.com/aws/aws-sdk-go-v2/service/rolesanywhere v1.23.7
	github.com/aws/aws-sdk-go-v2/service/s3 v1.102.2
	github.com/aws/aws-sdk-go-v2/service/sagemaker v1.250.2
	github.com/aws/aws-sdk-go-v2/service/secretsmanager v1.41.9
	github.com/aws/aws-sdk-go-v2/service/securityhub v1.71.2
	github.com/aws/aws-sdk-go-v2/service/sfn v1.43.0
	github.com/aws/aws-sdk-go-v2/service/signer v1.33.6
	github.com/aws/aws-sdk-go-v2/service/sns v1.39.19
	github.com/aws/aws-sdk-go-v2/service/sqs v1.42.29
	github.com/aws/aws-sdk-go-v2/service/ssm v1.68.8
	github.com/aws/aws-sdk-go-v2/service/storagegateway v1.44.3
	github.com/aws/aws-sdk-go-v2/service/sts v1.42.3
	github.com/aws/aws-sdk-go-v2/service/timestreamwrite v1.35.25
	github.com/aws/aws-sdk-go-v2/service/transfer v1.72.2
	github.com/aws/aws-sdk-go-v2/service/vpclattice v1.22.2
	github.com/aws/aws-sdk-go-v2/service/workspaces v1.68.3
	github.com/aws/aws-sdk-go-v2/service/workspacesweb v1.40.7
	github.com/aws/aws-sdk-go-v2/service/xray v1.37.3
	github.com/aws/constructs-go/constructs/v10 v10.6.0
	github.com/aws/jsii-runtime-go v1.133.0
	github.com/aws/smithy-go v1.27.1
	github.com/google/uuid v1.6.0
	github.com/santhosh-tekuri/jsonschema/v5 v5.3.1
	github.com/spf13/cobra v1.10.2
	github.com/xuri/excelize/v2 v2.10.1
	gopkg.in/yaml.v3 v3.0.1
)

require (
	github.com/Masterminds/semver/v3 v3.5.0 // indirect
	github.com/aws/aws-sdk-go-v2/aws/protocol/eventstream v1.7.11 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.25 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.4.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.7.29 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.30 // indirect
	github.com/aws/aws-sdk-go-v2/service/appstream v1.60.5 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.10 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/checksum v1.9.18 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/endpoint-discovery v1.12.2 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/s3shared v1.19.25 // indirect
	github.com/aws/aws-sdk-go-v2/service/sesv2 v1.62.4 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.1.1 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.30.19 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.36.2 // indirect
	github.com/cdklabs/awscdk-asset-awscli-go/awscliv1/v2 v2.2.273 // indirect
	github.com/cdklabs/awscdk-asset-node-proxy-agent-go/nodeproxyagentv6/v2 v2.1.1 // indirect
	github.com/cdklabs/cloud-assembly-schema-go/awscdkcloudassemblyschema/v53 v53.25.0 // indirect
	github.com/fatih/color v1.19.0 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.14 // indirect
	github.com/mattn/go-isatty v0.0.22 // indirect
	github.com/richardlehane/mscfb v1.0.6 // indirect
	github.com/richardlehane/msoleps v1.0.6 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	github.com/tiendc/go-deepcopy v1.7.2 // indirect
	github.com/xuri/efp v0.0.1 // indirect
	github.com/xuri/nfp v0.0.2-0.20250530014748-2ddeb826f9a9 // indirect
	github.com/yuin/goldmark v1.7.16 // indirect
	golang.org/x/crypto v0.51.0 // indirect
	golang.org/x/lint v0.0.0-20241112194109-818c5a804067 // indirect
	golang.org/x/mod v0.36.0 // indirect
	golang.org/x/net v0.54.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.44.0 // indirect
	golang.org/x/telemetry v0.0.0-20260508192327-42602be52be6 // indirect
	golang.org/x/text v0.37.0 // indirect
	golang.org/x/tools v0.45.0 // indirect
	golang.org/x/tools/cmd/godoc v0.1.0-deprecated // indirect
	golang.org/x/tools/godoc v0.1.0-deprecated // indirect
)
