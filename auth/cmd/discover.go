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
	"fmt"
	"net/url"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
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

func (cmd *DiscoverCommand) Run(ctx server.Cmd) error {
	authClient, endpoint, err := clientFor(ctx)
	if err != nil {
		return err
	}

	// Set the endpoint
	if cmd.Endpoint == "" {
		cmd.Endpoint = endpoint
		if stored_endpoint := ctx.GetString(endpointStoreKeyPrefix); stored_endpoint != "" {
			cmd.Endpoint = stored_endpoint
		}
	}

	// Check the endpoint
	url, err := url.Parse(cmd.Endpoint)
	if err != nil {
		return fmt.Errorf("invalid endpoint URL: %w", err)
	} else if url.Scheme != types.SchemeSecure && url.Scheme != types.SchemeInsecure {
		return fmt.Errorf("endpoint URL must have http or https scheme")
	} else if url.Host == "" {
		return fmt.Errorf("endpoint URL must have a host")
	}

	config, err := discoverAuthMetadata(ctx, authClient, cmd.Endpoint)
	if err != nil {
		return err
	}
	fmt.Println(types.Stringify(config))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func discoverAuthMetadata(ctx server.Cmd, authClient *auth.Client, endpoint string) (*auth.Config, error) {
	endpoint = strings.TrimSpace(endpoint)
	if ctx != nil {
		if issuer := strings.TrimSpace(ctx.GetString(issuerStoreKey(endpoint))); issuer != "" {
			meta, err := authClient.DiscoverFromIssuer(ctx.Context(), issuer)
			if err == nil && meta != nil && len(meta.AuthorizationServers) > 0 {
				return meta, nil
			}
		}
	}

	var meta *auth.Config
	if err := authClient.DoAuthWithContext(ctx.Context(), nil, nil, client.OptReqEndpoint(endpoint)); err != nil {
		meta_, discoverErr := authClient.DiscoverWithError(ctx.Context(), err)
		if discoverErr == nil && meta_ != nil {
			meta = meta_
		}
	}
	if meta != nil {
		return meta, nil
	}
	meta, err := authClient.Discover(ctx.Context(), endpoint)
	if err != nil {
		return nil, fmt.Errorf("failed to discover auth server metadata: %w", err)
	}
	return meta, nil
}
