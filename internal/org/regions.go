// Package org handles AWS Organizations enumeration, cross-account
// assume-role, and region listing for multi-region scanning.
package org

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// CommercialDefaults returns the default region list for commercial AWS partition.
// Used when no --regions flag is provided and EC2 DescribeRegions is unavailable.
func CommercialDefaults() []string {
	return []string{
		"us-east-1", "us-east-2", "us-west-1", "us-west-2",
		"ap-south-1", "ap-southeast-1", "ap-southeast-2",
		"ap-northeast-1", "ap-northeast-2", "ap-northeast-3",
		"eu-west-1", "eu-west-2", "eu-west-3", "eu-central-1", "eu-north-1",
		"sa-east-1", "ca-central-1",
	}
}

// IndianBFSIDefaults returns the regulator-relevant regions for Indian BFSI:
// ap-south-1 (Mumbai) and ap-south-2 (Hyderabad), with us-east-1 for global services.
func IndianBFSIDefaults() []string {
	return []string{"ap-south-1", "ap-south-2", "us-east-1"}
}

// EnabledRegions queries EC2 DescribeRegions to enumerate regions enabled in
// the caller's account. Falls back to CommercialDefaults on error.
func EnabledRegions(ctx context.Context, cfg aws.Config) ([]string, error) {
	c := ec2.NewFromConfig(cfg)
	out, err := c.DescribeRegions(ctx, &ec2.DescribeRegionsInput{
		AllRegions: aws.Bool(false),
	})
	if err != nil {
		return CommercialDefaults(), fmt.Errorf("DescribeRegions: %w (using defaults)", err)
	}
	regions := make([]string, 0, len(out.Regions))
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}
	return regions, nil
}
