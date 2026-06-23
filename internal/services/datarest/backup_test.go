package datarest

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/backup"
	backuptypes "github.com/aws/aws-sdk-go-v2/service/backup/types"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	kmstypes "github.com/aws/aws-sdk-go-v2/service/kms/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

// fakeBackupKMS is a hand-rolled kmsDescribeKeyAPI for unit-testing the opaque
// key-id -> custody-tier resolution. managerByKeyArn maps an EncryptionKeyArn to the
// KeyManager DescribeKey should report; errFor forces a DescribeKey failure for an
// arn (to prove the scanner stays "undetermined" and never guesses on error).
type fakeBackupKMS struct {
	managerByKeyArn map[string]kmstypes.KeyManagerType
	errFor          map[string]error
	calls           int
}

func (f *fakeBackupKMS) DescribeKey(ctx context.Context, in *kms.DescribeKeyInput, optFns ...func(*kms.Options)) (*kms.DescribeKeyOutput, error) {
	f.calls++
	id := ""
	if in.KeyId != nil {
		id = *in.KeyId
	}
	if f.errFor != nil {
		if err, ok := f.errFor[id]; ok {
			return nil, err
		}
	}
	if f.managerByKeyArn != nil {
		if m, ok := f.managerByKeyArn[id]; ok {
			return &kms.DescribeKeyOutput{KeyMetadata: &kmstypes.KeyMetadata{KeyManager: m}}, nil
		}
	}
	return &kms.DescribeKeyOutput{}, nil // nil metadata -> resolver stays undetermined
}

// fakeBackupClient is a hand-rolled backupAPI for unit-testing the scanner's
// pagination + per-vault error handling without a live AWS client. listPages is
// returned page-by-page (each ListBackupVaults call consumes the next page) and
// the NextToken is wired so the scanner loops through every page; listErr forces
// a top-level ListBackupVaults failure. describeErrFor names vaults whose
// DescribeBackupVault must fail; describeKeyFor supplies the EncryptionKeyArn for
// the rest (empty string -> AWS-owned default key).
type fakeBackupClient struct {
	listPages      []*backup.ListBackupVaultsOutput
	listCalls      int
	listErr        error
	describeErrFor map[string]error
	describeKeyFor map[string]string
}

func (f *fakeBackupClient) ListBackupVaults(ctx context.Context, in *backup.ListBackupVaultsInput, optFns ...func(*backup.Options)) (*backup.ListBackupVaultsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listCalls >= len(f.listPages) {
		return &backup.ListBackupVaultsOutput{}, nil
	}
	out := f.listPages[f.listCalls]
	f.listCalls++
	return out, nil
}

func (f *fakeBackupClient) DescribeBackupVault(ctx context.Context, in *backup.DescribeBackupVaultInput, optFns ...func(*backup.Options)) (*backup.DescribeBackupVaultOutput, error) {
	name := ""
	if in.BackupVaultName != nil {
		name = *in.BackupVaultName
	}
	if err, ok := f.describeErrFor[name]; ok {
		return nil, err
	}
	out := &backup.DescribeBackupVaultOutput{BackupVaultName: in.BackupVaultName}
	if key, ok := f.describeKeyFor[name]; ok && key != "" {
		k := key
		out.EncryptionKeyArn = &k
	}
	return out, nil
}

func backupSptr(s string) *string { return &s }

func vault(name string) backuptypes.BackupVaultListMember {
	n := name
	return backuptypes.BackupVaultListMember{BackupVaultName: &n}
}

// assetByID indexes scan output by ResourceID for assertions.
func assetByID(assets []models.CryptoAsset) map[string]models.CryptoAsset {
	m := map[string]models.CryptoAsset{}
	for _, a := range assets {
		m[a.ResourceID] = a
	}
	return m
}

// TestBackupScanPaginates verifies the ListBackupVaults NextToken loop: a fake
// that returns 2 pages (NextToken on page 1) must yield BOTH pages' vaults as
// assets. Without the pagination loop, only the first page's vault survives.
func TestBackupScanPaginates(t *testing.T) {
	client := &fakeBackupClient{
		listPages: []*backup.ListBackupVaultsOutput{
			{
				BackupVaultList: []backuptypes.BackupVaultListMember{vault("vault-page1")},
				NextToken:       backupSptr("tok-page2"),
			},
			{
				BackupVaultList: []backuptypes.BackupVaultListMember{vault("vault-page2")},
				// no NextToken -> last page
			},
		},
		describeKeyFor: map[string]string{}, // both -> AWS-owned default key
	}
	assets, err := BackupScanner{}.scan(context.Background(), client, &fakeBackupKMS{}, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	if client.listCalls != 2 {
		t.Errorf("expected ListBackupVaults to be called 2 times (paginated), got %d", client.listCalls)
	}
	got := assetByID(assets)
	for _, want := range []string{"vault-page1", "vault-page2"} {
		if _, ok := got[want]; !ok {
			t.Errorf("expected vault %q from a paginated page to appear as an asset; assets=%v", want, backupKeys(got))
		}
	}
}

// TestBackupScanListErrorPropagates verifies the owner's incompleteness decision:
// a top-level ListBackupVaults failure (denied/rate-limited) must make the scan
// VISIBLY incomplete by returning a non-nil error — NOT a silent empty success.
func TestBackupScanListErrorPropagates(t *testing.T) {
	sentinel := errors.New("AccessDeniedException: not authorized to perform backup:ListBackupVaults")
	client := &fakeBackupClient{listErr: sentinel}
	_, err := BackupScanner{}.scan(context.Background(), client, &fakeBackupKMS{}, "111122223333", "us-east-1")
	if err == nil {
		t.Fatal("expected scan to return a non-nil error when ListBackupVaults fails, got nil (silent empty success)")
	}
	if !errors.Is(err, sentinel) {
		t.Errorf("expected returned error to wrap the ListBackupVaults failure, got: %v", err)
	}
}

// TestBackupScanDescribeErrorDoesNotDrop verifies the honesty fix: a per-vault
// DescribeBackupVault failure must NOT silently drop the vault by omission (which
// would read as a clean all-clear). The vault must still appear as an asset, but
// with PostureUnknown and an explanatory note — never a fabricated SymmetricOnly
// all-clear and never a fabricated NoEncryption alarm. The sibling vault whose
// describe succeeds must still be classified normally.
func TestBackupScanDescribeErrorDoesNotDrop(t *testing.T) {
	client := &fakeBackupClient{
		listPages: []*backup.ListBackupVaultsOutput{
			{BackupVaultList: []backuptypes.BackupVaultListMember{vault("vault-broken"), vault("vault-ok")}},
		},
		describeErrFor: map[string]error{
			"vault-broken": errors.New("AccessDeniedException: not authorized to perform backup:DescribeBackupVault"),
		},
		describeKeyFor: map[string]string{}, // vault-ok -> AWS-owned default
	}
	assets, err := BackupScanner{}.scan(context.Background(), client, &fakeBackupKMS{}, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error (a per-vault describe failure must not abort the scan): %v", err)
	}
	got := assetByID(assets)
	broken, ok := got["vault-broken"]
	if !ok {
		t.Fatalf("vault-broken was silently dropped after DescribeBackupVault failed; assets=%v", backupKeys(got))
	}
	if posture := broken.Properties["posture"]; posture != string(models.PostureUnknown) {
		t.Errorf("expected vault-broken posture=%q after a describe failure, got %q", models.PostureUnknown, posture)
	}
	if broken.Properties["note"] == "" {
		t.Errorf("expected vault-broken to carry an explanatory note after a describe failure, got empty")
	}
	// The healthy sibling must still be classified normally (no collateral drop).
	okv, ok := got["vault-ok"]
	if !ok {
		t.Fatalf("vault-ok was dropped though its describe succeeded; assets=%v", backupKeys(got))
	}
	if posture := okv.Properties["posture"]; posture != string(models.PostureSymmetricOnly) {
		t.Errorf("expected vault-ok posture=%q, got %q", models.PostureSymmetricOnly, posture)
	}
}

// TestBackupScanPostureHonesty verifies the at-rest honesty mapping: AWS Backup
// encrypts every vault, so posture is unconditionally SymmetricOnly — never
// NoEncryption. A vault with a CMK records that ARN; a vault without one records
// the AWS-owned/managed default key WITHOUT presenting a NoEncryption alarm.
func TestBackupScanPostureHonesty(t *testing.T) {
	const cmk = "arn:aws:kms:us-east-1:111122223333:key/cmk-1234"
	client := &fakeBackupClient{
		listPages: []*backup.ListBackupVaultsOutput{
			{BackupVaultList: []backuptypes.BackupVaultListMember{vault("vault-cmk"), vault("vault-default")}},
		},
		describeKeyFor: map[string]string{
			"vault-cmk": cmk,
			// "vault-default" absent -> empty EncryptionKeyArn -> AWS-owned default
		},
	}
	assets, err := BackupScanner{}.scan(context.Background(), client, &fakeBackupKMS{}, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan returned unexpected error: %v", err)
	}
	got := assetByID(assets)

	for _, name := range []string{"vault-cmk", "vault-default"} {
		a, ok := got[name]
		if !ok {
			t.Fatalf("expected vault %q as an asset; assets=%v", name, backupKeys(got))
		}
		// Every Backup vault is encrypted: posture must be SymmetricOnly, never NoEncryption.
		if posture := a.Properties["posture"]; posture != string(models.PostureSymmetricOnly) {
			t.Errorf("vault %q: expected posture %q (Backup always encrypts), got %q", name, models.PostureSymmetricOnly, posture)
		}
	}

	// CMK present -> recorded verbatim.
	if k := got["vault-cmk"].Properties["kmsKeyArn"]; k != cmk {
		t.Errorf("expected vault-cmk kmsKeyArn=%q, got %q", cmk, k)
	}
	// CMK absent -> AWS-owned default recorded, NOT a NoEncryption all-clear/alarm.
	if k := got["vault-default"].Properties["kmsKeyArn"]; k != "AWS_OWNED_KMS_KEY" {
		t.Errorf("expected vault-default kmsKeyArn=%q (AWS-owned default), got %q", "AWS_OWNED_KMS_KEY", k)
	}
}

func backupKeys(m map[string]models.CryptoAsset) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	return ks
}

// TestBackupKeyTierResolution verifies the opaque-key-id custody resolution: a vault
// whose EncryptionKeyArn is a raw key-id ARN is UNDETERMINED by string alone, then
// resolved via kms:DescribeKey -> KeyManager. AWS-managed -> aws-managed-default;
// CUSTOMER -> customer-cmk; a DescribeKey error -> STAYS undetermined (never guesses
// custody — the BFSI-safety contract). Also covers the no-API string-only branches.
func TestBackupKeyTierResolution(t *testing.T) {
	const awsManagedKeyID = "arn:aws:kms:ap-south-1:111122223333:key/aaaaaaaa-aws-managed"
	const customerKeyID = "arn:aws:kms:ap-south-1:111122223333:key/bbbbbbbb-customer-cmk"
	const deniedKeyID = "arn:aws:kms:ap-south-1:111122223333:key/cccccccc-denied"

	cases := []struct {
		name     string
		vault    string
		keyArn   string
		wantTier string
	}{
		{"empty -> aws-managed-default (no API)", "v-empty", "", tierAWSManagedDefault},
		{"aws/backup alias ARN -> aws-managed-default (no API)", "v-alias", "arn:aws:kms:ap-south-1:111122223333:alias/aws/backup", tierAWSManagedDefault},
		{"customer alias -> customer-cmk (no API)", "v-cust-alias", "alias/my-team-key", tierCustomerCMK},
		{"opaque key-id, KeyManager=AWS -> aws-managed-default", "v-awskey", awsManagedKeyID, tierAWSManagedDefault},
		{"opaque key-id, KeyManager=CUSTOMER -> customer-cmk", "v-custkey", customerKeyID, tierCustomerCMK},
		{"opaque key-id, DescribeKey denied -> stays undetermined", "v-denied", deniedKeyID, tierUndetermined},
	}

	vaults := make([]backuptypes.BackupVaultListMember, 0, len(cases))
	keyFor := map[string]string{}
	for _, c := range cases {
		vaults = append(vaults, vault(c.vault))
		keyFor[c.vault] = c.keyArn
	}
	client := &fakeBackupClient{
		listPages:      []*backup.ListBackupVaultsOutput{{BackupVaultList: vaults}},
		describeKeyFor: keyFor,
	}
	kmsFake := &fakeBackupKMS{
		managerByKeyArn: map[string]kmstypes.KeyManagerType{
			awsManagedKeyID: kmstypes.KeyManagerTypeAws,
			customerKeyID:   kmstypes.KeyManagerTypeCustomer,
		},
		errFor: map[string]error{deniedKeyID: errors.New("AccessDeniedException: kms:DescribeKey")},
	}
	assets, err := BackupScanner{}.scan(context.Background(), client, kmsFake, "111122223333", "us-east-1")
	if err != nil {
		t.Fatalf("scan error: %v", err)
	}
	got := assetByID(assets)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			a, ok := got[c.vault]
			if !ok {
				t.Fatalf("no asset for vault %q", c.vault)
			}
			if tier := a.Properties["keyTier"]; tier != c.wantTier {
				t.Errorf("vault %q: keyTier = %q, want %q", c.vault, tier, c.wantTier)
			}
			// Every backup vault is always encrypted: posture must stay symmetric-only,
			// NEVER no-encryption, regardless of custody tier.
			if p := a.Properties["posture"]; p != string(models.PostureSymmetricOnly) {
				t.Errorf("vault %q: posture = %q, want symmetric-only", c.vault, p)
			}
		})
	}
	// The 3 string-only cases must NOT have triggered a DescribeKey call; the 3
	// opaque key-id cases each trigger exactly one -> 3 total.
	if kmsFake.calls != 3 {
		t.Errorf("expected 3 DescribeKey calls (one per opaque key-id vault), got %d", kmsFake.calls)
	}
}
