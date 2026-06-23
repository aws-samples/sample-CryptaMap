package transit

import (
	"context"
	"fmt"
	"os"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	amtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"

	"github.com/aws-samples/cryptamap/internal/services"
	"github.com/aws-samples/cryptamap/pkg/models"
)

// AppMeshScanner inspects AWS App Mesh virtual nodes for listener (m)TLS.
//
// App Mesh TLS is OPT-IN and off by default: a virtual node with no listener TLS
// block, or Mode=DISABLED, accepts plaintext -> NoEncryption (a genuine finding,
// not a false all-clear). Mode=PERMISSIVE still accepts plaintext alongside TLS ->
// LegacyTLS (weakened). Mode=STRICT enforces TLS with a classical (ACM/file/SDS)
// RSA/ECDSA cert -> NonPQCClassical (no PQ option). Reported per virtual node as
// the weakest listener posture.
type AppMeshScanner struct{}

// Name returns the canonical service identifier.
func (AppMeshScanner) Name() string { return "appmesh" }

// Category returns the primary CryptaMap category.
func (AppMeshScanner) Category() models.Category { return models.CategoryDataInTransit }

// appMeshAPI is the minimal slice of the appmesh client this scanner uses. All
// three calls are NextToken-paginated (ListMeshes/ListVirtualNodes) or per-node
// (DescribeVirtualNode); defining it as an interface keeps the pagination + error
// handling logic unit-testable with a fake (the concrete *appmesh.Client
// satisfies it).
type appMeshAPI interface {
	ListMeshes(ctx context.Context, in *appmesh.ListMeshesInput, optFns ...func(*appmesh.Options)) (*appmesh.ListMeshesOutput, error)
	ListVirtualNodes(ctx context.Context, in *appmesh.ListVirtualNodesInput, optFns ...func(*appmesh.Options)) (*appmesh.ListVirtualNodesOutput, error)
	DescribeVirtualNode(ctx context.Context, in *appmesh.DescribeVirtualNodeInput, optFns ...func(*appmesh.Options)) (*appmesh.DescribeVirtualNodeOutput, error)
}

// Scan enumerates meshes -> virtual nodes, describing each for its listener TLS.
func (s AppMeshScanner) Scan(ctx context.Context, cfg aws.Config) ([]models.CryptoAsset, error) {
	client := appmesh.NewFromConfig(cfg)
	accountID := services.AccountID(ctx, cfg)
	region := cfg.Region
	return s.scan(ctx, client, accountID, region)
}

// scan holds the testable core: it paginates ListMeshes -> ListVirtualNodes and
// describes each node's listener TLS. A top-level ListMeshes error is propagated
// so a denied/throttled scan is VISIBLY incomplete rather than a clean-looking
// empty success; a per-mesh ListVirtualNodes error is logged and that mesh is
// skipped (no silent corruption of other meshes).
func (s AppMeshScanner) scan(ctx context.Context, client appMeshAPI, accountID, region string) ([]models.CryptoAsset, error) {
	assets := []models.CryptoAsset{}
	var meshToken *string
	for {
		meshes, err := client.ListMeshes(ctx, &appmesh.ListMeshesInput{NextToken: meshToken})
		if err != nil {
			return nil, fmt.Errorf("appmesh ListMeshes: %w", err)
		}
		for _, m := range meshes.Meshes {
			if m.MeshName == nil {
				continue
			}
			var vnToken *string
			for {
				vns, verr := client.ListVirtualNodes(ctx, &appmesh.ListVirtualNodesInput{MeshName: m.MeshName, MeshOwner: m.MeshOwner, NextToken: vnToken})
				if verr != nil {
					fmt.Fprintf(os.Stderr, "appmesh ListVirtualNodes %s: %v\n", *m.MeshName, verr)
					break
				}
				for _, vn := range vns.VirtualNodes {
					if vn.VirtualNodeName == nil {
						continue
					}
					a, ok := s.describeNode(ctx, client, accountID, region, m.MeshName, m.MeshOwner, vn)
					if ok {
						assets = append(assets, a)
					}
					if services.TruncationCapReached(len(assets), s.Name(), region) {
						return assets, nil
					}
				}
				if vns.NextToken == nil || *vns.NextToken == "" {
					break
				}
				vnToken = vns.NextToken
			}
		}
		if meshes.NextToken == nil || *meshes.NextToken == "" {
			break
		}
		meshToken = meshes.NextToken
	}
	return assets, nil
}

func (s AppMeshScanner) describeNode(ctx context.Context, client appMeshAPI, accountID, region string, meshName, meshOwner *string, vn amtypes.VirtualNodeRef) (models.CryptoAsset, bool) {
	id := *vn.VirtualNodeName
	if vn.Arn != nil && *vn.Arn != "" {
		id = *vn.Arn
	}
	out, err := client.DescribeVirtualNode(ctx, &appmesh.DescribeVirtualNodeInput{
		MeshName: meshName, MeshOwner: meshOwner, VirtualNodeName: vn.VirtualNodeName,
	})
	if err != nil || out.VirtualNode == nil || out.VirtualNode.Spec == nil {
		if err != nil {
			fmt.Fprintf(os.Stderr, "appmesh DescribeVirtualNode %s: %v\n", id, err)
		}
		return models.CryptoAsset{}, false
	}

	// Weakest listener TLS posture across the node's listeners. Seed from the
	// FIRST listener and fold the rest — seeding from NoEncryption would poison
	// the weakest-wins fold (NoEncryption ranks weakest, so a STRICT/PERMISSIVE
	// node would always collapse to NoEncryption). A node with zero listeners
	// has no TLS surface and is correctly NoEncryption.
	posture := models.PostureNoEncryption // zero-listeners default -> plaintext
	mode := "none"
	for i, l := range out.VirtualNode.Spec.Listeners {
		lp, lm := appMeshListenerPosture(l.Tls)
		mode = lm
		if i == 0 {
			posture = lp
		} else {
			posture = weakerTransitPosture(posture, lp)
		}
	}

	props := services.TLSProtocolProps("", "app-mesh-mtls")
	if posture == models.PostureNoEncryption {
		props = services.NoEncryption()
	}
	a := services.NewAsset("appmesh", models.CategoryDataInTransit, accountID, region, id, "AWS::AppMesh::VirtualNode", props)
	services.PostureProperty(&a, posture)
	a.Properties["listenerTlsMode"] = mode
	switch posture {
	case models.PostureNoEncryption:
		a.Properties["note"] = "App Mesh virtual node has no enforced listener TLS (TLS disabled or absent); plaintext is accepted."
	case models.PostureLegacyTLS:
		a.Properties["note"] = "App Mesh listener TLS mode is PERMISSIVE: TLS is offered but plaintext is still accepted."
	}
	return a, true
}

// appMeshListenerPosture maps a listener's TLS block to a posture + mode label.
func appMeshListenerPosture(tls *amtypes.ListenerTls) (models.CryptoPosture, string) {
	if tls == nil {
		return models.PostureNoEncryption, "none"
	}
	switch tls.Mode {
	case amtypes.ListenerTlsModeStrict:
		return models.PostureNonPQCClassical, "STRICT"
	case amtypes.ListenerTlsModePermissive:
		return models.PostureLegacyTLS, "PERMISSIVE"
	case amtypes.ListenerTlsModeDisabled:
		return models.PostureNoEncryption, "DISABLED"
	}
	return models.PostureNoEncryption, string(tls.Mode)
}

// weakerTransitPosture returns the weaker (more concerning) of two transit
// postures: NoEncryption < LegacyTLS < NonPQCClassical < PQCHybrid.
func weakerTransitPosture(a, b models.CryptoPosture) models.CryptoPosture {
	rank := func(p models.CryptoPosture) int {
		switch p {
		case models.PostureNoEncryption:
			return 0
		case models.PostureLegacyTLS:
			return 1
		case models.PostureNonPQCClassical:
			return 2
		case models.PosturePQCHybrid, models.PosturePQCReady:
			return 3
		}
		return 2
	}
	if rank(b) < rank(a) {
		return b
	}
	return a
}
