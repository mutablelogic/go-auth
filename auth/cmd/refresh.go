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
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RefreshCommand struct {
	Endpoint string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *RefreshCommand) Run(globals server.Cmd) (err error) {
	return withAuth(globals, "RefreshCommand", types.Stringify(cmd), func(ctx context.Context, authclient *auth.Client) error {
		// Get the endpoint, defaulting to the global HTTP client endpoint
		if endpoint, err := endpoint(globals, authclient, cmd.Endpoint, ""); err != nil {
			return err
		} else {
			cmd.Endpoint = endpoint.String()
		}

		// Do the refresh
		refreshed, err := refreshStoredToken(globals, ctx, authclient, cmd.Endpoint)
		if err != nil {
			return err
		}

		// Print the refreshed token
		fmt.Println(types.Stringify(refreshed))
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func refreshStoredToken(ctx server.Cmd, spanctx context.Context, authClient *auth.Client, endpoint string) (*oauth2.Token, error) {
	meta, err := discoverAuthMetadata(ctx, spanctx, authClient, endpoint)
	if err != nil {
		return nil, err
	}
	return refreshStoredTokenWithMetadata(ctx, spanctx, authClient, meta, endpoint)
}

func refreshStoredTokenWithMetadata(ctx server.Cmd, spanctx context.Context, authClient *auth.Client, meta *auth.Config, endpoint string) (*oauth2.Token, error) {
	token, err := storedToken(ctx, endpoint)
	if err != nil {
		return nil, err
	} else if token == nil {
		return nil, fmt.Errorf("no stored token for endpoint %q", endpoint)
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
	clientID := strings.TrimSpace(ctx.GetString(clientIDStoreKey(nil, issuer)))
	clientSecret := strings.TrimSpace(ctx.GetString(clientSecretStoreKey(nil, issuer)))

	oauthConfig, err := auth.OAuth2Config(config, clientID, clientSecret)
	if err != nil {
		return nil, err
	}
	refreshed, err := authClient.RefreshToken(spanctx, oauthConfig, token)
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
