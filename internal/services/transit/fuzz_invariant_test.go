package transit

// fuzz_invariant_test.go is the ADVERSARIAL property/invariant test for the
// data-in-transit scanner classification cores. See the datarest sibling for the
// full rationale. It exists specifically because the AppMesh weakest-wins fold
// bug (STRICT/PERMISSIVE nodes ALL collapsing to no-encryption from a NoEncryption
// seed) was a SYSTEMIC mislabel that per-scanner opt-in tests missed; this test
// throws hostile inputs at a cross-section of transit cores and asserts the
// honesty contract systemically.
//
// Hostile shapes per scanner core (Scanner{}.scan(ctx, fakeClient, acct, region)):
//
//	(a) a top-level List/Describe error  -> MUST propagate (visibly incomplete);
//	(b) a per-resource Describe error    -> failed resource never gets a confident
//	                                        no-encryption verdict (Unknown/skip/propagate);
//	(c)/(d) nil/empty output + empty page -> no panic, no error, every emitted
//	                                        asset still honest.
//
// Invariants: no panic; top-level error propagates with nil/empty assets; every
// emitted asset has a 7-enum posture + non-empty Service; no asset from a FAILED
// read carries a confident no-encryption / symmetric-only verdict.

import (
	"context"
	"errors"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/appmesh"
	"github.com/aws/aws-sdk-go-v2/service/directconnect"
	"github.com/aws/aws-sdk-go-v2/service/ecs"
	"github.com/aws/aws-sdk-go-v2/service/eks"
	elb "github.com/aws/aws-sdk-go-v2/service/elasticloadbalancing"
	"github.com/aws/aws-sdk-go-v2/service/elasticloadbalancingv2"
	"github.com/aws/aws-sdk-go-v2/service/lambda"

	amtypes "github.com/aws/aws-sdk-go-v2/service/appmesh/types"

	"github.com/aws-samples/cryptamap/pkg/models"
)

var transitValidPostures = map[models.CryptoPosture]bool{
	models.PostureNoEncryption:    true,
	models.PostureLegacyTLS:       true,
	models.PostureNonPQCClassical: true,
	models.PostureSymmetricOnly:   true,
	models.PosturePQCHybrid:       true,
	models.PosturePQCReady:        true,
	models.PostureUnknown:         true,
}

func transitAssertHonest(t *testing.T, scanner string, assets []models.CryptoAsset, fromFailedRead bool) {
	t.Helper()
	for i, a := range assets {
		if a.Service == "" {
			t.Errorf("[%s] asset #%d has empty Service (escapes the registry)", scanner, i)
		}
		p := models.CryptoPosture(a.Properties["posture"])
		if !transitValidPostures[p] {
			t.Errorf("[%s] asset #%d has posture %q outside the 7-value enum", scanner, i, p)
		}
		if fromFailedRead && (p == models.PostureNoEncryption || p == models.PostureSymmetricOnly) {
			t.Errorf("[%s] asset #%d produced a confident %q verdict on a FAILED read (fabricated verdict); note=%q",
				scanner, i, p, a.Properties["note"])
		}
	}
}

func transitRunCase(t *testing.T, scanner, scenario string, wantErr, fromFailedRead bool, fn func() ([]models.CryptoAsset, error)) {
	t.Helper()
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("[%s/%s] PANIC on hostile input: %v", scanner, scenario, r)
		}
	}()
	assets, err := fn()
	if wantErr {
		if err == nil {
			t.Errorf("[%s/%s] expected a propagated error, got nil (silent empty success)", scanner, scenario)
		}
		if len(assets) != 0 {
			t.Errorf("[%s/%s] expected no assets on a top-level read error, got %d", scanner, scenario, len(assets))
		}
	}
	transitAssertHonest(t, scanner, assets, fromFailedRead)
}

var transitErrHostile = errors.New("AccessDeniedException: hostile-fuzz denied read")

// nlb: DescribeLoadBalancers + DescribeListeners + DescribeSSLPolicies.
type fuzzNLBClient struct{ errTop, errResource bool }

func (f *fuzzNLBClient) DescribeLoadBalancers(ctx context.Context, in *elasticloadbalancingv2.DescribeLoadBalancersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeLoadBalancersOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	return &elasticloadbalancingv2.DescribeLoadBalancersOutput{}, nil
}
func (f *fuzzNLBClient) DescribeListeners(ctx context.Context, in *elasticloadbalancingv2.DescribeListenersInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeListenersOutput, error) {
	if f.errResource {
		return nil, transitErrHostile
	}
	return &elasticloadbalancingv2.DescribeListenersOutput{}, nil
}
func (f *fuzzNLBClient) DescribeSSLPolicies(ctx context.Context, in *elasticloadbalancingv2.DescribeSSLPoliciesInput, _ ...func(*elasticloadbalancingv2.Options)) (*elasticloadbalancingv2.DescribeSSLPoliciesOutput, error) {
	if f.errResource {
		return nil, transitErrHostile
	}
	return &elasticloadbalancingv2.DescribeSSLPoliciesOutput{}, nil
}

// classicelb: DescribeLoadBalancers.
type fuzzClassicELBClient struct{ errTop bool }

func (f *fuzzClassicELBClient) DescribeLoadBalancers(ctx context.Context, in *elb.DescribeLoadBalancersInput, _ ...func(*elb.Options)) (*elb.DescribeLoadBalancersOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	return &elb.DescribeLoadBalancersOutput{}, nil
}

// appmesh: ListMeshes + ListVirtualNodes + DescribeVirtualNode.
type fuzzAppMeshClient struct{ errTop, errResource bool }

func (f *fuzzAppMeshClient) ListMeshes(ctx context.Context, in *appmesh.ListMeshesInput, _ ...func(*appmesh.Options)) (*appmesh.ListMeshesOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	if f.errResource {
		name := "mesh1"
		return &appmesh.ListMeshesOutput{Meshes: []amtypes.MeshRef{{MeshName: &name}}}, nil
	}
	return &appmesh.ListMeshesOutput{}, nil
}
func (f *fuzzAppMeshClient) ListVirtualNodes(ctx context.Context, in *appmesh.ListVirtualNodesInput, _ ...func(*appmesh.Options)) (*appmesh.ListVirtualNodesOutput, error) {
	if f.errResource {
		// Return one node so the per-node DescribeVirtualNode error path is hit.
		name := "vn1"
		return &appmesh.ListVirtualNodesOutput{VirtualNodes: []amtypes.VirtualNodeRef{{VirtualNodeName: &name}}}, nil
	}
	return &appmesh.ListVirtualNodesOutput{}, nil
}
func (f *fuzzAppMeshClient) DescribeVirtualNode(ctx context.Context, in *appmesh.DescribeVirtualNodeInput, _ ...func(*appmesh.Options)) (*appmesh.DescribeVirtualNodeOutput, error) {
	if f.errResource {
		return nil, transitErrHostile
	}
	return &appmesh.DescribeVirtualNodeOutput{}, nil
}

// ecs: ListClusters.
type fuzzECSClient struct{ errTop bool }

func (f *fuzzECSClient) ListClusters(ctx context.Context, in *ecs.ListClustersInput, _ ...func(*ecs.Options)) (*ecs.ListClustersOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	return &ecs.ListClustersOutput{}, nil
}

// eks: ListClusters.
type fuzzEKSClient struct{ errTop bool }

func (f *fuzzEKSClient) ListClusters(ctx context.Context, in *eks.ListClustersInput, _ ...func(*eks.Options)) (*eks.ListClustersOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	return &eks.ListClustersOutput{}, nil
}

// lambda: ListFunctions.
type fuzzLambdaClient struct{ errTop bool }

func (f *fuzzLambdaClient) ListFunctions(ctx context.Context, in *lambda.ListFunctionsInput, _ ...func(*lambda.Options)) (*lambda.ListFunctionsOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	return &lambda.ListFunctionsOutput{}, nil
}

// directconnect: DescribeConnections.
type fuzzDirectConnectClient struct{ errTop bool }

func (f *fuzzDirectConnectClient) DescribeConnections(ctx context.Context, in *directconnect.DescribeConnectionsInput, _ ...func(*directconnect.Options)) (*directconnect.DescribeConnectionsOutput, error) {
	if f.errTop {
		return nil, transitErrHostile
	}
	return &directconnect.DescribeConnectionsOutput{}, nil
}

// TestFuzzTransitScannerInvariants drives the transit cores with hostile inputs.
func TestFuzzTransitScannerInvariants(t *testing.T) {
	ctx := context.Background()
	const acct, region = "111122223333", "us-east-1"

	t.Run("topLevelError_propagates", func(t *testing.T) {
		transitRunCase(t, "nlb", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return NLBScanner{}.scan(ctx, &fuzzNLBClient{errTop: true}, acct, region)
		})
		transitRunCase(t, "classicelb", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return ClassicELBScanner{}.scan(ctx, &fuzzClassicELBClient{errTop: true}, acct, region)
		})
		transitRunCase(t, "appmesh", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return AppMeshScanner{}.scan(ctx, &fuzzAppMeshClient{errTop: true}, acct, region)
		})
		transitRunCase(t, "ecs", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return ECSScanner{}.scan(ctx, &fuzzECSClient{errTop: true}, acct, region)
		})
		transitRunCase(t, "eks", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return EKSScanner{}.scan(ctx, &fuzzEKSClient{errTop: true}, acct, region)
		})
		transitRunCase(t, "lambda", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return LambdaScanner{}.scan(ctx, &fuzzLambdaClient{errTop: true}, acct, region)
		})
		transitRunCase(t, "directconnect", "topErr", true, true, func() ([]models.CryptoAsset, error) {
			return DirectConnectScanner{}.scan(ctx, &fuzzDirectConnectClient{errTop: true}, acct, region)
		})
	})

	// Per-resource Describe error. NOTE on AppMesh: a per-node DescribeVirtualNode
	// failure currently DROPS that node (describeNode returns ok=false) — a silent
	// drop, not an Unknown emission. That is weaker than the datarest contract, but
	// the property this test guards is the one the AppMesh bug violated: a node
	// that IS emitted must never be a fabricated no-encryption from a failed/empty
	// read. The drop is documented honestly in the agent report; this case proves
	// no panic + no fabricated verdict, and that the top-level list still succeeds.
	t.Run("perResourceError_neverFabricatesVerdict", func(t *testing.T) {
		transitRunCase(t, "nlb", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return NLBScanner{}.scan(ctx, &fuzzNLBClient{errResource: true}, acct, region)
		})
		transitRunCase(t, "appmesh", "resErr", false, true, func() ([]models.CryptoAsset, error) {
			return AppMeshScanner{}.scan(ctx, &fuzzAppMeshClient{errResource: true}, acct, region)
		})
	})

	t.Run("emptyAndNilOutput_noPanic", func(t *testing.T) {
		transitRunCase(t, "nlb", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return NLBScanner{}.scan(ctx, &fuzzNLBClient{}, acct, region)
		})
		transitRunCase(t, "classicelb", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return ClassicELBScanner{}.scan(ctx, &fuzzClassicELBClient{}, acct, region)
		})
		transitRunCase(t, "appmesh", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return AppMeshScanner{}.scan(ctx, &fuzzAppMeshClient{}, acct, region)
		})
		transitRunCase(t, "ecs", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return ECSScanner{}.scan(ctx, &fuzzECSClient{}, acct, region)
		})
		transitRunCase(t, "eks", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return EKSScanner{}.scan(ctx, &fuzzEKSClient{}, acct, region)
		})
		transitRunCase(t, "lambda", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return LambdaScanner{}.scan(ctx, &fuzzLambdaClient{}, acct, region)
		})
		transitRunCase(t, "directconnect", "empty", false, false, func() ([]models.CryptoAsset, error) {
			return DirectConnectScanner{}.scan(ctx, &fuzzDirectConnectClient{}, acct, region)
		})
	})
}
