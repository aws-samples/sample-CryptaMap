package org

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/organizations"
	"github.com/aws/aws-sdk-go-v2/service/organizations/types"
)

// AccountInfo summarises one Org account.
type AccountInfo struct {
	ID     string
	Name   string
	Email  string
	Status string
	OU     string
}

// ListAccounts enumerates accounts via Organizations:ListAccounts.
// Caller must have organizations:ListAccounts on the management account.
func ListAccounts(ctx context.Context, cfg aws.Config) ([]AccountInfo, error) {
	c := organizations.NewFromConfig(cfg)
	var accounts []AccountInfo
	var nextToken *string
	for {
		out, err := c.ListAccounts(ctx, &organizations.ListAccountsInput{NextToken: nextToken})
		if err != nil {
			return nil, fmt.Errorf("ListAccounts: %w", err)
		}
		for _, a := range out.Accounts {
			if a.Status != types.AccountStatusActive {
				continue
			}
			info := AccountInfo{
				Status: string(a.Status),
			}
			if a.Id != nil {
				info.ID = *a.Id
			}
			if a.Name != nil {
				info.Name = *a.Name
			}
			if a.Email != nil {
				info.Email = *a.Email
			}
			accounts = append(accounts, info)
		}
		if out.NextToken == nil {
			break
		}
		nextToken = out.NextToken
	}
	return accounts, nil
}
