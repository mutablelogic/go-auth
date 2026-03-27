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
	"encoding/json"
	"fmt"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth/pkg/httpclient/auth"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RefreshCommand struct {
	Endpoint     string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
	ClientID     string `name:"client-id" help:"OAuth client ID. Defaults to the stored client ID for the issuer."`
	ClientSecret string `name:"client-secret" help:"OAuth client secret. Defaults to the stored client secret for the issuer when required by the provider."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *RefreshCommand) Run(ctx server.Cmd) error {
	authClient, endpoint, err := clientFor(ctx)
	if err != nil {
		return err
	} else if cmd.Endpoint == "" {
		cmd.Endpoint = endpoint
	}
	refreshed, err := refreshStoredToken(ctx, authClient, cmd.Endpoint, cmd.ClientID, cmd.ClientSecret)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(refreshed, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal refreshed token: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func refreshStoredToken(ctx server.Cmd, authClient *auth.Client, endpoint, clientID, clientSecret string) (*oauth2.Token, error) {
	endpoint = strings.TrimSpace(endpoint)

	token, err := storedToken(ctx, endpoint)
	if err != nil {
		return nil, err
	}
	if token == nil {
		return nil, fmt.Errorf("no stored token for endpoint %q", endpoint)
	}

	meta, err := discoverAuthMetadata(ctx, authClient, endpoint)
	if err != nil {
		return nil, err
	}
	serverMeta, err := meta.AuthorizationServerForFlow()
	if err != nil {
		return nil, err
	}
	config, err := serverMeta.AuthorizationCodeConfig()
	if err != nil {
		return nil, err
	}

	issuer := strings.TrimSpace(config.Issuer)
	if issuer == "" {
		issuer = strings.TrimSpace(serverMeta.Issuer)
	}
	clientID = strings.TrimSpace(clientID)
	if clientID == "" {
		clientID = strings.TrimSpace(ctx.GetString(clientIDStoreKey(nil, issuer)))
	}
	clientSecret = strings.TrimSpace(clientSecret)
	if clientSecret == "" {
		clientSecret = strings.TrimSpace(ctx.GetString(clientSecretStoreKey(nil, issuer)))
	}

	oauthConfig, err := auth.OAuth2Config(config, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	refreshed, err := authClient.RefreshToken(ctx.Context(), oauthConfig, token)
	if err != nil {
		return nil, err
	}
	if err := storeToken(ctx, endpoint, issuer, refreshed); err != nil {
		return nil, err
	}
	if err := storeClientCredentials(ctx, nil, issuer, clientID, clientSecret); err != nil {
		return nil, err
	}
	return refreshed, nil
}

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
