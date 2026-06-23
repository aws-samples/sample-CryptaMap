// Command gen-policy is CryptaMap's single-source-of-truth IAM scanner-policy
// generator. It is the sibling of cmd/gen-ts and cmd/gen-knowledge.
//
// The scanner roles use a CUSTOM least-privilege policy rather than the broad
// AWS-managed ReadOnlyAccess. The authoritative action set lives HERE as a Go
// literal list (readActions) so that when a new scanner is added, its required
// IAM action is added in exactly ONE place. From that literal the generator
// projects a committed JSON artifact (cdk/policy/scanner-actions.json) that the
// CDK security stack and the member-account StackSet template both consume, so a
// scanner's IAM action can never silently drift from the code.
//
//	go run ./cmd/gen-policy            # rewrite the committed artifact(s)
//	go run ./cmd/gen-policy -check     # fail if any artifact is stale (CI guard)
//
// Two artifacts are emitted, both deterministic / offline / stdlib-only:
//
//  1. cdk/policy/scanner-actions.json — the structured contract consumed by
//     cdk/lib/security-stack.ts (imported via resolveJsonModule). It carries the
//     full read-action list plus the three resource-scoped WRITE statements the
//     orchestrator (and only the orchestrator) is granted. Write resources are
//     emitted as portable placeholder tokens that the CDK substitutes with real
//     ARNs / pseudo-parameters at synth time.
//
//  2. cdk/templates/scanner-role-template.json — the SERVICE_MANAGED StackSet
//     body deployed to every member account. The member scanner role gets the
//     READ actions ONLY (no writes). gen-policy rewrites the inline policy's
//     Action array in place from readActions, leaving the rest of the template
//     (trust policy, parameters, tags) untouched, so the member role can never
//     drift from the same source list either.
//
// IMPORTANT classification note: codebuild:BatchGetProjects is a READ (it returns
// project CONFIGURATION, not build data) despite the "Get...Batch" naming, and is
// intentionally in readActions.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

// readActions is the authoritative least-privilege READ action set granted to
// every CryptaMap scanner role (member-account role AND the in-account
// orchestrator/local scanner role). Add a new scanner's required action HERE and
// nowhere else; `make generate-policy` re-projects it into both committed
// artifacts and `make check-policy` (CI) fails the build on drift.
//
// Order is preserved verbatim in the emitted artifact, so the list is also the
// stable diff surface for review. Keep it grouped/commented as today.
var readActions = []string{
	// identity / org enumeration
	"sts:GetCallerIdentity",
	"organizations:ListAccounts",
	// ec2 inventory + transit surfaces
	"ec2:DescribeRegions",
	"ec2:DescribeVolumes",
	"ec2:DescribeKeyPairs",
	"ec2:DescribeClientVpnEndpoints",
	"ec2:DescribeVpnConnections",
	// s3 at-rest
	"s3:ListAllMyBuckets",
	"s3:GetBucketEncryption",
	// kms
	"kms:DescribeKey",
	"kms:ListKeys",
	"kms:ListAliases",
	"kms:GetKeyRotationStatus",
	"kms:DescribeCustomKeyStores",
	// messaging
	"sqs:ListQueues",
	"sqs:GetQueueAttributes",
	"sns:ListTopics",
	"sns:GetTopicAttributes",
	// analytics / search
	"redshift-serverless:ListNamespaces",
	"aoss:ListCollections",
	"es:ListDomainNames",
	"es:DescribeDomain",
	"elasticmapreduce:ListSecurityConfigurations",
	"elasticmapreduce:DescribeSecurityConfiguration",
	// databases
	"dynamodb:ListTables",
	"dynamodb:DescribeTable",
	"docdb-elastic:ListClusters",
	"docdb-elastic:GetCluster",
	// logs / migration / backup
	"logs:DescribeLogGroups",
	"dms:DescribeReplicationInstances",
	"backup:ListBackupVaults",
	"backup:DescribeBackupVault",
	// relational
	"rds:DescribeDBInstances",
	"rds:DescribeDBClusters",
	"rds:DescribeDBParameters",
	"rds:DescribeDBClusterParameters",
	// secrets / cache / warehouse
	"secretsmanager:ListSecrets",
	"elasticache:DescribeReplicationGroups",
	"redshift:DescribeClusters",
	// quicksight / connect-profiles / workspaces-web
	"quicksight:DescribeKeyRegistration",
	"profile:ListDomains",
	"profile:GetDomain",
	"workspaces-web:ListPortals",
	"workspaces-web:GetPortal",
	// codebuild (BatchGetProjects returns project CONFIG, not data => READ)
	"codebuild:ListProjects",
	"codebuild:BatchGetProjects",
	// mgn / kinesis / mq / lightsail / msk
	"mgn:DescribeReplicationConfigurationTemplates",
	"kinesis:ListStreams",
	"kinesis:DescribeStreamSummary",
	"mq:ListBrokers",
	"mq:DescribeBroker",
	"lightsail:GetInstances",
	"kafka:ListClustersV2",
	// step functions / fsx / emr-serverless / firehose / memorydb
	"states:ListStateMachines",
	"states:DescribeStateMachine",
	"fsx:DescribeFileSystems",
	"emr-serverless:ListApplications",
	"firehose:ListDeliveryStreams",
	"firehose:DescribeDeliveryStream",
	"memorydb:DescribeClusters",
	// kendra / sagemaker / dax / eventbridge / glue
	"kendra:ListIndices",
	"kendra:DescribeIndex",
	"sagemaker:ListDomains",
	"sagemaker:DescribeDomain",
	"dax:DescribeClusters",
	"events:ListEventBuses",
	"events:DescribeEventBus",
	"glue:GetDataCatalogEncryptionSettings",
	// storage gateway
	"storagegateway:ListGateways",
	"storagegateway:ListFileShares",
	"storagegateway:DescribeNFSFileShares",
	"storagegateway:DescribeSMBFileShares",
	// keyspaces / workspaces / qldb
	// NOTE: Neptune scanners (neptune.go, neptune_transit.go) call the
	// RDS-compatible management API (Describe{DBClusters,DBInstances,
	// DBClusterParameters}) which is authorized under the rds: prefix
	// (already granted above). The neptune-db: prefix is Neptune's DATA-plane
	// (graph query) namespace and is NOT used by any scanner, so no
	// neptune-db: grant appears here.
	"cassandra:Select",
	"workspaces:DescribeWorkspaces",
	"qldb:ListLedgers",
	"qldb:DescribeLedger",
	// ssm
	"ssm:DescribeParameters",
	"ssm:DescribeInstanceInformation",
	// bedrock
	"bedrock:ListAgents",
	"bedrock:GetAgent",
	"bedrock:ListCustomModels",
	"bedrock:GetCustomModel",
	"bedrock:ListGuardrails",
	"bedrock:GetGuardrail",
	"bedrock:ListKnowledgeBases",
	// timestream / kinesis-analytics / athena / xray / efs
	"timestream:ListDatabases",
	"timestream:DescribeEndpoints",
	"kinesisanalytics:ListApplications",
	"kinesisanalytics:DescribeApplication",
	"athena:ListWorkGroups",
	"athena:GetWorkGroup",
	"xray:GetEncryptionConfig",
	"elasticfilesystem:DescribeFileSystems",
	// cognito / payment-cryptography / cloudhsm / cloudtrail
	"cognito-idp:ListUserPools",
	"payment-cryptography:ListKeys",
	"payment-cryptography:GetKey",
	"cloudhsm:DescribeClusters",
	"cloudtrail:LookupEvents",
	// cloudfront / iam server certs / ses
	"cloudfront:ListDistributions",
	"cloudfront:ListPublicKeys",
	"iam:ListServerCertificates",
	"iam:GetServerCertificate",
	"ses:ListEmailIdentities",
	"ses:GetEmailIdentity",
	// acm / appstream / iot certs / acm-pca / signer / roles-anywhere
	"acm:ListCertificates",
	"acm:DescribeCertificate",
	"appstream:DescribeDirectoryConfigs",
	"iot:ListCertificates",
	"iot:DescribeCertificate",
	"acm-pca:ListCertificateAuthorities",
	"signer:ListSigningProfiles",
	"signer:GetSigningProfile",
	"rolesanywhere:ListTrustAnchors",
	// eks / elb(v2) / vpc-lattice
	"eks:ListClusters",
	"elasticloadbalancing:DescribeLoadBalancers",
	"elasticloadbalancing:DescribeListeners",
	"elasticloadbalancing:DescribeSSLPolicies",
	"vpc-lattice:ListServices",
	"vpc-lattice:GetService",
	"vpc-lattice:ListListeners",
	// iot domains / things / apigateway
	"iot:DescribeDomainConfiguration",
	"iot:ListDomainConfigurations",
	"iot:ListThings",
	"apigateway:GET",
	// transfer / directconnect / lambda / appsync
	"transfer:ListServers",
	"transfer:DescribeServer",
	"transfer:DescribeSecurityPolicy",
	"directconnect:DescribeConnections",
	"lambda:ListFunctions",
	"appsync:ListGraphqlApis",
	// directory service / ecs / appmesh / global accelerator
	"ds:DescribeDirectories",
	"ds:DescribeLDAPSSettings",
	"ecs:ListClusters",
	"appmesh:ListMeshes",
	"appmesh:ListVirtualNodes",
	"appmesh:DescribeVirtualNode",
	"globalaccelerator:ListAccelerators",
	"globalaccelerator:ListListeners",
	// ecr
	"ecr:DescribeRepositories",
	"ecr:DescribeImages",
}

// writeStmt is one resource-scoped WRITE statement granted to the orchestrator
// role ONLY (never to a member scanner role). Resource carries a portable
// placeholder token (see resource placeholders below) that the CDK substitutes
// with the real ARN / CloudFormation pseudo-parameter at synth time.
type writeStmt struct {
	Sid      string `json:"sid"`
	Action   string `json:"action"`
	Resource string `json:"resource"`
}

// orchestratorWrites are the EXACTLY THREE resource-scoped writes the
// orchestrator needs to persist scan output. The member scanner role gets NONE
// of these. Placeholders (resolved by security-stack.ts):
//
//	{RESULTS_BUCKET_ARN}    -> props.resultsBucket.bucketArn
//	{SCANS_TABLE_ARN}       -> props.scansTable.tableArn
//	{SECURITYHUB_PRODUCT_ARN} -> arn:<partition>:securityhub:<region>:<account>:product/<account>/default
//
// for THIS (orchestrator/Audit) account+region only.
var orchestratorWrites = []writeStmt{
	{
		Sid:      "WriteScanResultsToBucket",
		Action:   "s3:PutObject",
		Resource: "{RESULTS_BUCKET_ARN}/*",
	},
	{
		Sid:      "RecordScanInTable",
		Action:   "dynamodb:PutItem",
		Resource: "{SCANS_TABLE_ARN}",
	},
	{
		Sid:      "ImportFindingsToSecurityHub",
		Action:   "securityhub:BatchImportFindings",
		Resource: "{SECURITYHUB_PRODUCT_ARN}",
	},
}

// policyArtifact is the structure projected to cdk/policy/scanner-actions.json.
type policyArtifact struct {
	Doc               string      `json:"_doc"`
	ReadActions       []string    `json:"readActions"`
	OrchestratorWrite []writeStmt `json:"orchestratorWrites"`
}

const (
	artifactPath = "cdk/policy/scanner-actions.json"
	templatePath = "cdk/templates/scanner-role-template.json"
)

func main() {
	check := flag.Bool("check", false, "fail if any on-disk artifact differs from the literals projection (CI staleness guard)")
	flag.Parse()

	guardDuplicates()

	artifact := renderArtifact()
	template, err := renderTemplate()
	if err != nil {
		fmt.Fprintf(os.Stderr, "gen-policy: render template: %v\n", err)
		os.Exit(1)
	}

	targets := []struct {
		path string
		want []byte
	}{
		{artifactPath, artifact},
		{templatePath, template},
	}

	if *check {
		stale := false
		for _, t := range targets {
			got, err := os.ReadFile(t.path)
			if err != nil {
				fmt.Fprintf(os.Stderr, "gen-policy -check: read %s: %v\n", t.path, err)
				os.Exit(1)
			}
			if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(t.want)) {
				fmt.Fprintf(os.Stderr, "ERROR: %s is stale. Run 'make generate-policy' and commit.\n", t.path)
				stale = true
			}
		}
		if stale {
			os.Exit(1)
		}
		fmt.Printf("gen-policy: artifacts up to date (%d read actions, %d orchestrator writes)\n",
			len(readActions), len(orchestratorWrites))
		return
	}

	for _, t := range targets {
		if err := os.WriteFile(t.path, t.want, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "gen-policy: write %s: %v\n", t.path, err)
			os.Exit(1)
		}
	}
	fmt.Printf("gen-policy: wrote %s + %s (%d read actions, %d orchestrator writes)\n",
		artifactPath, templatePath, len(readActions), len(orchestratorWrites))
}

// guardDuplicates fails generation if the source list contains a duplicate
// action — a likely copy/paste error when adding a new scanner.
func guardDuplicates() {
	seen := map[string]bool{}
	var dups []string
	for _, a := range readActions {
		if seen[a] {
			dups = append(dups, a)
		}
		seen[a] = true
	}
	if len(dups) > 0 {
		fmt.Fprintf(os.Stderr, "gen-policy: duplicate read actions in source list: %v\n", dups)
		os.Exit(1)
	}
}

// renderArtifact projects the literals to the structured JSON contract consumed
// by the CDK. Deterministic, pretty-printed, trailing newline (matches gen-knowledge).
func renderArtifact() []byte {
	a := policyArtifact{
		Doc: "GENERATED by cmd/gen-policy; DO NOT EDIT. Single source of truth: readActions in cmd/gen-policy/main.go. " +
			"readActions is the least-privilege READ surface for ALL scanner roles. orchestratorWrites are the 3 resource-scoped " +
			"writes granted to the orchestrator role ONLY (member scanner roles get reads only). Regenerate with 'make generate-policy'; " +
			"CI ('make check-policy') fails on drift. Resource placeholders are substituted by cdk/lib/security-stack.ts at synth time.",
		ReadActions:       readActions,
		OrchestratorWrite: orchestratorWrites,
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(a); err != nil {
		fmt.Fprintf(os.Stderr, "gen-policy: marshal artifact: %v\n", err)
		os.Exit(1)
	}
	return buf.Bytes()
}

// renderTemplate reads the existing StackSet template, replaces ONLY the inline
// scanner policy's Action array with the read-action source list, and re-emits
// the whole document. Everything else (trust policy, parameters, tags, outputs)
// is preserved byte-for-byte up to JSON re-marshalling. The member scanner role
// gets READS ONLY — no orchestrator writes are ever injected here.
func renderTemplate() ([]byte, error) {
	raw, err := os.ReadFile(templatePath)
	if err != nil {
		return nil, err
	}
	// Decode into an ordered-preserving generic map. encoding/json sorts object
	// keys on re-marshal, so the on-disk template is itself a generated artifact
	// (the -check guard tolerates this because we compare the re-marshalled form,
	// and the committed file is produced by this same path).
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse %s: %w", templatePath, err)
	}

	stmt, err := scannerInlineStatement(doc)
	if err != nil {
		return nil, err
	}
	// Replace the Action array in place with the source read-action list.
	actions := make([]any, len(readActions))
	for i, a := range readActions {
		actions[i] = a
	}
	stmt["Action"] = actions

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetIndent("", "  ")
	enc.SetEscapeHTML(false)
	if err := enc.Encode(doc); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// scannerInlineStatement navigates the template to the single inline policy
// statement whose Action array gen-policy owns. It fails loudly if the template
// shape changed, so a structural edit can never silently leave the actions stale.
func scannerInlineStatement(doc map[string]any) (map[string]any, error) {
	resources, ok := doc["Resources"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template missing Resources object")
	}
	role, ok := resources["CryptaMapScannerRole"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("template missing Resources.CryptaMapScannerRole")
	}
	props, ok := role["Properties"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("scanner role missing Properties")
	}
	policies, ok := props["Policies"].([]any)
	if !ok || len(policies) == 0 {
		return nil, fmt.Errorf("scanner role missing inline Policies")
	}
	for _, p := range policies {
		pm, ok := p.(map[string]any)
		if !ok {
			continue
		}
		if pm["PolicyName"] != "CryptaMapScannerReadActions" {
			continue
		}
		pd, ok := pm["PolicyDocument"].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("CryptaMapScannerReadActions missing PolicyDocument")
		}
		stmts, ok := pd["Statement"].([]any)
		if !ok || len(stmts) == 0 {
			return nil, fmt.Errorf("CryptaMapScannerReadActions missing Statement")
		}
		sm, ok := stmts[0].(map[string]any)
		if !ok {
			return nil, fmt.Errorf("CryptaMapScannerReadActions Statement[0] not an object")
		}
		return sm, nil
	}
	return nil, fmt.Errorf("template missing inline policy named CryptaMapScannerReadActions (add it so gen-policy can own its Action array)")
}
