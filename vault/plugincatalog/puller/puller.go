// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: BUSL-1.1

package puller

import "github.com/hashicorp/vault/sdk/helper/consts"

type PullRequest struct {
	Type    consts.PluginType
	Name    string
	Version string
	SHA256  string
}

type PullResponse struct {
	SHA256 string
}

type Puller interface {
	Pull(*PullRequest) (*PullResponse, error)
}
