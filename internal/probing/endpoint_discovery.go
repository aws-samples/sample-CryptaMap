package probing

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// VPCEndpoint is a discovered VPC endpoint plus its DNS names.
type VPCEndpoint struct {
	ID          string
	ServiceName string
	State       string
	DNSNames    []string
}

// DiscoverVPCEndpoints enumerates VPC interface endpoints in a region.
func DiscoverVPCEndpoints(ctx context.Context, cfg aws.Config) ([]VPCEndpoint, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeVpcEndpoints(ctx, &ec2.DescribeVpcEndpointsInput{})
	if err != nil {
		return nil, fmt.Errorf("DescribeVpcEndpoints: %w", err)
	}
	endpoints := make([]VPCEndpoint, 0, len(out.VpcEndpoints))
	for _, e := range out.VpcEndpoints {
		ve := VPCEndpoint{}
		if e.VpcEndpointId != nil {
			ve.ID = *e.VpcEndpointId
		}
		if e.ServiceName != nil {
			ve.ServiceName = *e.ServiceName
		}
		ve.State = string(e.State)
		for _, d := range e.DnsEntries {
			if d.DnsName != nil {
				ve.DNSNames = append(ve.DNSNames, *d.DnsName)
			}
		}
		endpoints = append(endpoints, ve)
	}
	return endpoints, nil
}
