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
	"encoding/json"
	"fmt"
	"net/url"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserInfoCommand struct {
	Endpoint string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *UserInfoCommand) Run(globals server.Cmd) (err error) {
	return withAuth(globals, "AuthorizeCommand", types.Stringify(cmd), func(ctx context.Context, authclient *auth.Client) error {
		// Set the endpoint
		if cmd.Endpoint == "" {
			cmd.Endpoint = authclient.Endpoint
			if stored_endpoint := globals.GetString(endpointStoreKeyPrefix); stored_endpoint != "" {
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

		meta, err := discoverAuthMetadata(globals, ctx, authclient, cmd.Endpoint)
		if err != nil {
			return err
		}

		// Get the token
		token, err := storedToken(globals, cmd.Endpoint)
		if err != nil {
			return err
		}
		if token == nil {
			return fmt.Errorf("no stored token for endpoint %q", cmd.Endpoint)
		}
		if !token.Valid() {
			if token, err = refreshStoredTokenWithMetadata(globals, ctx, authclient, meta, cmd.Endpoint); err != nil {
				return err
			}
		}

		// Get the user info
		userinfo, err := userInfoForEndpointWithMetadata(ctx, authclient, meta, token)
		if err != nil {
			return err
		}

		data, err := json.MarshalIndent(userinfo, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal userinfo: %w", err)
		}
		fmt.Println(string(data))
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func userInfoForEndpointWithMetadata(ctx context.Context, authClient *auth.Client, meta *auth.Config, token *oauth2.Token) (*oidc.UserInfo, error) {
	if token == nil {
		return nil, fmt.Errorf("token is required")
	}
	serverMeta, err := meta.AuthorizationServerForUserInfo()
	if err != nil {
		return nil, err
	}
	return authClient.UserInfo(ctx, serverMeta.Oidc.UserInfoEndpoint, token)
}
