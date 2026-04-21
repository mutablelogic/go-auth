// Copyright 2026 David Thorpe
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package auth

import (
	"context"
	"fmt"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type DiscoverCommand struct {
	Endpoint string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *DiscoverCommand) Run(globals server.Cmd) (err error) {
	return withAuth(globals, "AuthorizeCommand", types.Stringify(cmd), func(ctx context.Context, authclient *auth.Client) error {
		// Get the endpoint, defaulting to the global HTTP client endpoint
		if endpoint, err := endpoint(globals, authclient, cmd.Endpoint, ""); err != nil {
			return err
		} else {
			cmd.Endpoint = endpoint.String()
		}

		// Discover the configuration
		config, err := discoverAuthMetadata(globals, ctx, authclient, cmd.Endpoint)
		if err != nil {
			return err
		}

		// Output the configuration
		fmt.Println(types.Stringify(config))
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func discoverAuthMetadata(ctx server.Cmd, spanctx context.Context, authClient *auth.Client, endpoint string) (*auth.Config, error) {
	if spanctx == nil && ctx != nil {
		spanctx = ctx.Context()
	}

	endpoint = strings.TrimSpace(endpoint)
	if ctx != nil {
		if issuer := strings.TrimSpace(ctx.GetString(issuerStoreKey(endpoint))); issuer != "" {
			meta, err := authClient.DiscoverFromIssuer(spanctx, issuer)
			if err == nil && meta != nil && len(meta.AuthorizationServers) > 0 {
				if strings.TrimSpace(meta.ProtectedResourceMetadata.Resource) == "" {
					meta.ProtectedResourceMetadata = oidc.ProtectedResourceMetadata{
						Resource:               endpoint,
						AuthorizationServers:   []string{issuer},
						BearerMethodsSupported: []string{"header"},
					}
				}
				return meta, nil
			}
		}
	}

	var meta *auth.Config
	if err := authClient.DoAuthWithContext(spanctx, nil, nil, client.OptReqEndpoint(endpoint)); err != nil {
		meta_, discoverErr := authClient.DiscoverWithError(spanctx, err)
		if discoverErr == nil && meta_ != nil {
			meta = meta_
		}
	}
	if meta != nil {
		return meta, nil
	}
	meta, err := authClient.Discover(spanctx, endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to discover auth server metadata: %w", err)
	}
	return meta, nil
}
