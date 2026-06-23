package main

import (
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/internal/services/datarest"
)

// registerDataAtRestImpl wires all 49 data-at-rest scanners.
func registerDataAtRestImpl(r *scanner.Registry) {
	r.Register(datarest.S3Scanner{})
	r.Register(datarest.EBSScanner{})
	r.Register(datarest.RDSScanner{})
	r.Register(datarest.DynamoDBScanner{})
	r.Register(datarest.RedshiftScanner{})
	r.Register(datarest.ElastiCacheScanner{})
	r.Register(datarest.DocumentDBScanner{})
	r.Register(datarest.NeptuneScanner{})
	r.Register(datarest.OpenSearchScanner{})
	r.Register(datarest.EFSScanner{})
	r.Register(datarest.FSxScanner{})
	r.Register(datarest.BackupScanner{})
	r.Register(datarest.GlueScanner{})
	r.Register(datarest.MSKScanner{})
	r.Register(datarest.SQSScanner{})
	r.Register(datarest.SNSScanner{})
	r.Register(datarest.KinesisScanner{})
	r.Register(datarest.SecretsManagerScanner{})
	r.Register(datarest.SSMScanner{})
	r.Register(datarest.CloudWatchLogsScanner{})
	r.Register(datarest.SageMakerScanner{})
	r.Register(datarest.WorkSpacesScanner{})
	r.Register(datarest.LightsailScanner{})
	r.Register(datarest.DMSScanner{})
	r.Register(datarest.TimestreamScanner{})
	r.Register(datarest.QLDBScanner{})
	r.Register(datarest.KeyspacesScanner{})
	r.Register(datarest.MemoryDBScanner{})
	r.Register(datarest.AthenaScanner{})
	r.Register(datarest.FirehoseScanner{})
	r.Register(datarest.EMRScanner{})
	r.Register(datarest.AmazonMQScanner{})
	r.Register(datarest.DAXScanner{})
	r.Register(datarest.RedshiftServerlessScanner{})
	r.Register(datarest.DocumentDBElasticScanner{})
	r.Register(datarest.StorageGatewayScanner{})
	r.Register(datarest.OpenSearchServerlessScanner{})
	r.Register(datarest.EMRServerlessScanner{})
	// Coverage-expansion (2026-06-15): 11 services promoted to v1 by the
	// skipped-services audit — each has its own, API-readable at-rest CMK surface
	// (CMK-vs-AWS-managed key tier; always AES-256, never a no-encryption verdict).
	r.Register(datarest.BedrockScanner{})
	r.Register(datarest.QuickSightScanner{})
	r.Register(datarest.ManagedFlinkScanner{})
	r.Register(datarest.EventBridgeScanner{})
	r.Register(datarest.StepFunctionsScanner{})
	r.Register(datarest.CustomerProfilesScanner{})
	r.Register(datarest.WorkSpacesWebScanner{})
	r.Register(datarest.CodeBuildScanner{})
	r.Register(datarest.XRayScanner{})
	r.Register(datarest.MGNScanner{})
	r.Register(datarest.KendraScanner{})
}
