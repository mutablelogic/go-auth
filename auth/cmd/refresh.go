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
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
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

	// Do the refresh
	refreshed, err := refreshStoredToken(ctx, authClient, cmd.Endpoint, cmd.ClientID, cmd.ClientSecret)
	if err != nil {
		return err
	}

	// Print the refreshed token
	fmt.Println(types.Stringify(refreshed))
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
	if err := storeToken(ctx, endpoint, issuer, storedProvider(ctx, endpoint), refreshed); err != nil {
		return nil, err
	}
	if err := storeClientCredentials(ctx, nil, issuer, clientID, clientSecret); err != nil {
		return nil, err
	}
	return refreshed, nil
}
