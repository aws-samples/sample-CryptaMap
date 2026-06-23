// Client-side port of internal/taxonomy/taxonomy.go. The redesign shows FRIENDLY
// names everywhere (never raw scanner ids like kms_spec). The CBOM SHOULD carry
// cryptamap:displayName / awsCategory / cryptoFunction / subAspect, and the
// helpers in this module PREFER those props when present; but for the live path
// (or any CBOM that omits the friendly props) we fall back to this registry,
// keyed by cryptamap:service.
//
// Source of truth: internal/taxonomy/taxonomy.go registry + aliases.

import type { CBOMComponent } from '../types';
import { getProp } from '../hooks/useScanData';

export interface TaxonomyEntry {
  scannerName: string;
  displayName: string;
  awsCategory: string;
  cryptoFunction: string; // '' when unknown
  subAspect: string; // '' when unknown
}

const F_AT_REST = 'data-at-rest';
const F_IN_TRANSIT = 'data-in-transit';
const F_CERT = 'certificates-pki';
const F_KEY = 'key-management';
const F_SDK = 'sdk-library';

const REGISTRY: Record<string, TaxonomyEntry> = {
  // --- data-at-rest ---
  s3: { scannerName: 's3', displayName: 'Amazon S3', awsCategory: 'Storage', cryptoFunction: F_AT_REST, subAspect: 'bucket-encryption' },
  ebs: { scannerName: 'ebs', displayName: 'Amazon EBS', awsCategory: 'Storage', cryptoFunction: F_AT_REST, subAspect: 'volume-encryption' },
  rds: { scannerName: 'rds', displayName: 'Amazon RDS', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'storage-encryption' },
  dynamodb: { scannerName: 'dynamodb', displayName: 'Amazon DynamoDB', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'table-encryption' },
  redshift: { scannerName: 'redshift', displayName: 'Amazon Redshift', awsCategory: 'Analytics', cryptoFunction: F_AT_REST, subAspect: 'cluster-encryption' },
  elasticache: { scannerName: 'elasticache', displayName: 'Amazon ElastiCache', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'at-rest-encryption' },
  documentdb: { scannerName: 'documentdb', displayName: 'Amazon DocumentDB', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'storage-encryption' },
  neptune: { scannerName: 'neptune', displayName: 'Amazon Neptune', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'storage-encryption' },
  opensearch: { scannerName: 'opensearch', displayName: 'Amazon OpenSearch Service', awsCategory: 'Analytics', cryptoFunction: F_AT_REST, subAspect: 'domain-encryption' },
  efs: { scannerName: 'efs', displayName: 'Amazon EFS', awsCategory: 'Storage', cryptoFunction: F_AT_REST, subAspect: 'filesystem-encryption' },
  fsx: { scannerName: 'fsx', displayName: 'Amazon FSx', awsCategory: 'Storage', cryptoFunction: F_AT_REST, subAspect: 'filesystem-encryption' },
  backup: { scannerName: 'backup', displayName: 'AWS Backup', awsCategory: 'Storage', cryptoFunction: F_AT_REST, subAspect: 'vault-encryption' },
  glue: { scannerName: 'glue', displayName: 'AWS Glue', awsCategory: 'Analytics', cryptoFunction: F_AT_REST, subAspect: 'security-config-encryption' },
  msk: { scannerName: 'msk', displayName: 'Amazon MSK', awsCategory: 'Analytics', cryptoFunction: F_AT_REST, subAspect: 'at-rest-encryption' },
  sqs: { scannerName: 'sqs', displayName: 'Amazon SQS', awsCategory: 'Application Integration', cryptoFunction: F_AT_REST, subAspect: 'queue-encryption' },
  sns: { scannerName: 'sns', displayName: 'Amazon SNS', awsCategory: 'Application Integration', cryptoFunction: F_AT_REST, subAspect: 'topic-encryption' },
  kinesis: { scannerName: 'kinesis', displayName: 'Amazon Kinesis Data Streams', awsCategory: 'Analytics', cryptoFunction: F_AT_REST, subAspect: 'stream-encryption' },
  secretsmanager: { scannerName: 'secretsmanager', displayName: 'AWS Secrets Manager', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_AT_REST, subAspect: 'secret-encryption' },
  ssm: { scannerName: 'ssm', displayName: 'AWS Systems Manager Parameter Store', awsCategory: 'Management & Governance', cryptoFunction: F_AT_REST, subAspect: 'parameter-encryption' },
  cloudwatchlogs: { scannerName: 'cloudwatchlogs', displayName: 'Amazon CloudWatch Logs', awsCategory: 'Management & Governance', cryptoFunction: F_AT_REST, subAspect: 'log-group-encryption' },
  sagemaker: { scannerName: 'sagemaker', displayName: 'Amazon SageMaker', awsCategory: 'Machine Learning', cryptoFunction: F_AT_REST, subAspect: 'volume-encryption' },
  workspaces: { scannerName: 'workspaces', displayName: 'Amazon WorkSpaces', awsCategory: 'End User Computing', cryptoFunction: F_AT_REST, subAspect: 'volume-encryption' },
  lightsail: { scannerName: 'lightsail', displayName: 'Amazon Lightsail', awsCategory: 'Compute', cryptoFunction: F_AT_REST, subAspect: 'disk-encryption' },
  dms: { scannerName: 'dms', displayName: 'AWS Database Migration Service', awsCategory: 'Migration & Transfer', cryptoFunction: F_AT_REST, subAspect: 'endpoint-encryption' },
  timestream: { scannerName: 'timestream', displayName: 'Amazon Timestream', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'table-encryption' },
  qldb: { scannerName: 'qldb', displayName: 'Amazon QLDB', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'ledger-encryption' },
  keyspaces: { scannerName: 'keyspaces', displayName: 'Amazon Keyspaces', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'table-encryption' },
  memorydb: { scannerName: 'memorydb', displayName: 'Amazon MemoryDB', awsCategory: 'Database', cryptoFunction: F_AT_REST, subAspect: 'at-rest-encryption' },

  // --- data-in-transit ---
  alb: { scannerName: 'alb', displayName: 'Application Load Balancer', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'listener-tls' },
  nlb: { scannerName: 'nlb', displayName: 'Network Load Balancer', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'listener-tls' },
  apigw_rest: { scannerName: 'apigw_rest', displayName: 'Amazon API Gateway (REST)', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'security-policy-tls' },
  apigw_http: { scannerName: 'apigw_http', displayName: 'Amazon API Gateway (HTTP)', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'security-policy-tls' },
  cloudfront: { scannerName: 'cloudfront', displayName: 'Amazon CloudFront', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'viewer-tls' },
  elasticache_transit: { scannerName: 'elasticache_transit', displayName: 'Amazon ElastiCache', awsCategory: 'Database', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-encryption' },
  documentdb_transit: { scannerName: 'documentdb_transit', displayName: 'Amazon DocumentDB', awsCategory: 'Database', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-tls' },
  rds_transit: { scannerName: 'rds_transit', displayName: 'Amazon RDS', awsCategory: 'Database', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-tls' },
  aurora_transit: { scannerName: 'aurora_transit', displayName: 'Amazon Aurora', awsCategory: 'Database', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-tls' },
  opensearch_transit: { scannerName: 'opensearch_transit', displayName: 'Amazon OpenSearch Service', awsCategory: 'Analytics', cryptoFunction: F_IN_TRANSIT, subAspect: 'node-to-node-tls' },
  msk_transit: { scannerName: 'msk_transit', displayName: 'Amazon MSK', awsCategory: 'Analytics', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-tls' },
  redshift_transit: { scannerName: 'redshift_transit', displayName: 'Amazon Redshift', awsCategory: 'Analytics', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-tls' },
  neptune_transit: { scannerName: 'neptune_transit', displayName: 'Amazon Neptune', awsCategory: 'Database', cryptoFunction: F_IN_TRANSIT, subAspect: 'in-transit-tls' },
  eks: { scannerName: 'eks', displayName: 'Amazon EKS', awsCategory: 'Compute', cryptoFunction: F_IN_TRANSIT, subAspect: 'endpoint-tls' },
  ecs: { scannerName: 'ecs', displayName: 'Amazon ECS', awsCategory: 'Compute', cryptoFunction: F_IN_TRANSIT, subAspect: 'service-tls' },
  lambda: { scannerName: 'lambda', displayName: 'AWS Lambda', awsCategory: 'Compute', cryptoFunction: F_IN_TRANSIT, subAspect: 'url-tls' },
  appsync: { scannerName: 'appsync', displayName: 'AWS AppSync', awsCategory: 'Application Integration', cryptoFunction: F_IN_TRANSIT, subAspect: 'endpoint-tls' },
  iotcore: { scannerName: 'iotcore', displayName: 'AWS IoT Core', awsCategory: 'Internet of Things', cryptoFunction: F_IN_TRANSIT, subAspect: 'mqtt-tls' },
  transferfamily: { scannerName: 'transferfamily', displayName: 'AWS Transfer Family', awsCategory: 'Migration & Transfer', cryptoFunction: F_IN_TRANSIT, subAspect: 'endpoint-tls' },
  vpn: { scannerName: 'vpn', displayName: 'AWS Site-to-Site VPN', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'ipsec-ike' },
  directconnect: { scannerName: 'directconnect', displayName: 'AWS Direct Connect', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'macsec' },
  globalaccelerator: { scannerName: 'globalaccelerator', displayName: 'AWS Global Accelerator', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_IN_TRANSIT, subAspect: 'listener-tls' },

  // --- certificates-pki ---
  acm: { scannerName: 'acm', displayName: 'AWS Certificate Manager', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_CERT, subAspect: 'public-certificate' },
  acmpca: { scannerName: 'acmpca', displayName: 'AWS Private CA', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_CERT, subAspect: 'private-ca' },
  iam_certs: { scannerName: 'iam_certs', displayName: 'AWS IAM Server Certificates', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_CERT, subAspect: 'server-certificate' },
  cloudfront_certs: { scannerName: 'cloudfront_certs', displayName: 'Amazon CloudFront Custom Certificates', awsCategory: 'Networking & Content Delivery', cryptoFunction: F_CERT, subAspect: 'viewer-certificate' },
  iot_certs: { scannerName: 'iot_certs', displayName: 'AWS IoT Core Device Certificates', awsCategory: 'Internet of Things', cryptoFunction: F_CERT, subAspect: 'device-certificate' },

  // --- key-management ---
  kms_spec: { scannerName: 'kms_spec', displayName: 'AWS KMS', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_KEY, subAspect: 'key-spec' },
  kms_usage: { scannerName: 'kms_usage', displayName: 'AWS KMS', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_KEY, subAspect: 'key-usage' },
  kms_rotation: { scannerName: 'kms_rotation', displayName: 'AWS KMS', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_KEY, subAspect: 'key-rotation' },
  cloudhsm: { scannerName: 'cloudhsm', displayName: 'AWS CloudHSM', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_KEY, subAspect: 'hsm-cluster' },
  secrets_rotation: { scannerName: 'secrets_rotation', displayName: 'AWS Secrets Manager', awsCategory: 'Security, Identity & Compliance', cryptoFunction: F_KEY, subAspect: 'secret-rotation' },

  // --- sdk-library ---
  lambda_runtime: { scannerName: 'lambda_runtime', displayName: 'AWS Lambda', awsCategory: 'Compute', cryptoFunction: F_SDK, subAspect: 'runtime-sdk-version' },
  container_images: { scannerName: 'container_images', displayName: 'Amazon ECS/EKS Container Images', awsCategory: 'Compute', cryptoFunction: F_SDK, subAspect: 'image-sdk-version' },
  ec2_ssm: { scannerName: 'ec2_ssm', displayName: 'Amazon EC2 (via SSM Inventory)', awsCategory: 'Compute', cryptoFunction: F_SDK, subAspect: 'instance-sdk-inventory' },
};

// aliases widens lookup for short / non-scanner service ids used by the mock
// generator (mirrors internal/taxonomy/taxonomy.go aliases).
const ALIASES: Record<string, string> = {
  kms: 'kms_spec',
};

function humanize(name: string): string {
  return name
    .replace(/_/g, ' ')
    .split(' ')
    .map((w) => (w ? w[0].toUpperCase() + w.slice(1) : w))
    .join(' ');
}

/** Look up the friendly taxonomy entry for a raw scanner service id. */
export function lookup(service: string | undefined): TaxonomyEntry {
  if (!service) return { scannerName: '', displayName: 'Unknown', awsCategory: 'Other', cryptoFunction: '', subAspect: '' };
  const direct = REGISTRY[service];
  if (direct) return direct;
  const canon = ALIASES[service];
  if (canon && REGISTRY[canon]) return REGISTRY[canon];
  return { scannerName: service, displayName: humanize(service), awsCategory: 'Other', cryptoFunction: '', subAspect: '' };
}

// The four "derived" facet accessors below PREFER the explicit cryptamap:*
// friendly property when present, falling back to the taxonomy lookup keyed by
// cryptamap:service. This keeps the live path (props present) and the mock
// path identical at the call site.

export function displayName(c: CBOMComponent): string {
  return getProp(c, 'cryptamap:displayName') ?? lookup(getProp(c, 'cryptamap:service')).displayName;
}

export function awsCategory(c: CBOMComponent): string {
  return getProp(c, 'cryptamap:awsCategory') ?? lookup(getProp(c, 'cryptamap:service')).awsCategory;
}

export function cryptoFunction(c: CBOMComponent): string {
  return (
    getProp(c, 'cryptamap:cryptoFunction') ??
    lookup(getProp(c, 'cryptamap:service')).cryptoFunction ??
    'unknown'
  );
}

export function subAspect(c: CBOMComponent): string {
  return getProp(c, 'cryptamap:subAspect') ?? lookup(getProp(c, 'cryptamap:service')).subAspect;
}
