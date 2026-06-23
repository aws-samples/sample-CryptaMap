package main

import (
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/internal/services/certmgmt"
	"github.com/aws-samples/cryptamap/internal/services/keymgmt"
	"github.com/aws-samples/cryptamap/internal/services/runtime"
	"github.com/aws-samples/cryptamap/internal/services/sdkpqc"
	// data-at-rest and transit packages registered after their subagents land.
)

// registerAllScanners wires every per-service scanner into the registry.
// Wires 99 scanners covering data-at-rest (49), data-in-transit (27),
// certificate management (10), key management (9), SDK/library PQC (3), and
// runtime evidence (1, CloudTrail KMS data-plane).
func registerAllScanners(r *scanner.Registry) {
	registerCertMgmt(r)
	registerKeyMgmt(r)
	registerSDKPQC(r)
	registerDataAtRestImpl(r)
	registerTransitImpl(r)
	registerRuntimeEvidence(r)
}

func registerCertMgmt(r *scanner.Registry) {
	r.Register(certmgmt.ACMScanner{})
	r.Register(certmgmt.ACMPCAScanner{})
	r.Register(certmgmt.IAMCertsScanner{})
	r.Register(certmgmt.CloudFrontCertsScanner{})
	r.Register(certmgmt.IoTCertsScanner{})
	r.Register(certmgmt.RolesAnywhereScanner{})
	r.Register(certmgmt.SignerScanner{})
	r.Register(certmgmt.CloudFrontKeyGroupsScanner{})
	// Coverage-expansion (2026-06-15): 2 signing/cert surfaces promoted to v1 by
	// the skipped-services audit — SES DKIM (classical RSA email signing) and
	// AppStream 2.0 certificate-based workforce auth (classical X.509 trust).
	r.Register(certmgmt.SESDKIMScanner{})
	r.Register(certmgmt.AppStreamCertAuthScanner{})
}

func registerKeyMgmt(r *scanner.Registry) {
	r.Register(keymgmt.KMSSpecScanner{})
	r.Register(keymgmt.KMSUsageScanner{})
	r.Register(keymgmt.KMSRotationScanner{})
	r.Register(keymgmt.CloudHSMScanner{})
	r.Register(keymgmt.SecretsRotationScanner{})
	r.Register(keymgmt.PaymentCryptographyScanner{})
	r.Register(keymgmt.CognitoScanner{})
	r.Register(keymgmt.EC2KeyPairsScanner{})
	r.Register(keymgmt.KMSCustomKeyStoreScanner{})
}

func registerSDKPQC(r *scanner.Registry) {
	r.Register(sdkpqc.LambdaRuntimeScanner{})
	r.Register(sdkpqc.ContainerImagesScanner{})
	r.Register(sdkpqc.EC2SSMScanner{})
}

func registerRuntimeEvidence(r *scanner.Registry) {
	r.Register(runtime.CloudTrailEvidenceScanner{})
}
