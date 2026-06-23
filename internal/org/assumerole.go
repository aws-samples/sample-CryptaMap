package org

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials/stscreds"
	"github.com/aws/aws-sdk-go-v2/service/sts"
)

// AssumeRole returns an aws.Config configured to use temporary credentials from
// assuming roleArn in the target account. externalID is optional but recommended.
func AssumeRole(ctx context.Context, base aws.Config, roleArn, externalID, sessionName string) aws.Config {
	stsClient := sts.NewFromConfig(base)
	provider := stscreds.NewAssumeRoleProvider(stsClient, roleArn, func(o *stscreds.AssumeRoleOptions) {
		if externalID != "" {
			o.ExternalID = aws.String(externalID)
		}
		if sessionName != "" {
			o.RoleSessionName = sessionName
		} else {
			o.RoleSessionName = "cryptamap-scanner"
		}
	})
	cfg := base.Copy()
	cfg.Credentials = aws.NewCredentialsCache(provider)
	return cfg
}

// RoleARN builds a standard ARN for a member-account scanner role.
func RoleARN(accountID, roleName string) string {
	return fmt.Sprintf("arn:aws:iam::%s:role/%s", accountID, roleName)
}

// CallerIdentity returns the active account ID for the given config.
func CallerIdentity(ctx context.Context, cfg aws.Config) (accountID, arn string, err error) {
	c := sts.NewFromConfig(cfg)
	out, err := c.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return "", "", fmt.Errorf("GetCallerIdentity: %w", err)
	}
	if out.Account != nil {
		accountID = *out.Account
	}
	if out.Arn != nil {
		arn = *out.Arn
	}
	return
}
