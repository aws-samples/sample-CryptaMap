package main

import (
	"github.com/aws-samples/cryptamap/internal/scanner"
	"github.com/aws-samples/cryptamap/internal/services/transit"
)

// registerTransitImpl wires all 27 in-transit scanners.
func registerTransitImpl(r *scanner.Registry) {
	r.Register(transit.ALBScanner{})
	r.Register(transit.NLBScanner{})
	r.Register(transit.APIGWRestScanner{})
	r.Register(transit.APIGWHTTPScanner{})
	r.Register(transit.CloudFrontScanner{})
	r.Register(transit.ElastiCacheTransitScanner{})
	r.Register(transit.DocumentDBTransitScanner{})
	r.Register(transit.RDSTransitScanner{})
	r.Register(transit.AuroraTransitScanner{})
	r.Register(transit.OpenSearchTransitScanner{})
	r.Register(transit.MSKTransitScanner{})
	r.Register(transit.RedshiftTransitScanner{})
	r.Register(transit.NeptuneTransitScanner{})
	r.Register(transit.EKSScanner{})
	r.Register(transit.ECSScanner{})
	r.Register(transit.LambdaScanner{})
	r.Register(transit.AppSyncScanner{})
	r.Register(transit.IoTCoreScanner{})
	r.Register(transit.TransferFamilyScanner{})
	r.Register(transit.VPNScanner{})
	r.Register(transit.DirectConnectScanner{})
	r.Register(transit.GlobalAcceleratorScanner{})
	r.Register(transit.ClientVPNScanner{})
	r.Register(transit.VPCLatticeScanner{})
	r.Register(transit.ClassicELBScanner{})
	r.Register(transit.AppMeshScanner{})
	r.Register(transit.DirectoryServiceScanner{})
}
