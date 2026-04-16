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
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	authschema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserInfoCommand struct {
	Endpoint     string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
	ClientID     string `name:"client-id" help:"OAuth client ID. Defaults to the stored client ID for the issuer when a refresh is needed."`
	ClientSecret string `name:"client-secret" help:"OAuth client secret. Defaults to the stored client secret for the issuer when a refresh is needed."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *UserInfoCommand) Run(ctx server.Cmd) error {
	authClient, endpoint, err := clientFor(ctx)
	if err != nil {
		return err
	} else if cmd.Endpoint == "" {
		cmd.Endpoint = endpoint
	}

	token, err := storedToken(ctx, cmd.Endpoint)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("no stored token for endpoint %q", cmd.Endpoint)
	}
	if !token.Valid() {
		if token, err = refreshStoredToken(ctx, authClient, cmd.Endpoint, cmd.ClientID, cmd.ClientSecret); err != nil {
			return err
		}
	}

	userinfo, err := userInfoForEndpoint(ctx, authClient, cmd.Endpoint, token)
	if err != nil {
		return err
	}

	data, err := json.MarshalIndent(userinfo, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal userinfo: %w", err)
	}
	fmt.Println(string(data))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE FUNCTIONS

func userInfoForEndpoint(ctx server.Cmd, authClient *auth.Client, endpoint string, token *oauth2.Token) (*authschema.UserInfo, error) {
	endpoint = strings.TrimSpace(endpoint)
	if token == nil {
		return nil, fmt.Errorf("token is required")
	}

	meta, err := discoverAuthMetadata(ctx, authClient, endpoint)
	if err != nil {
		return nil, err
	}
	serverMeta, err := meta.AuthorizationServerForUserInfo()
	if err != nil {
		return nil, err
	}
	userinfo, err := authClient.UserInfo(ctx.Context(), serverMeta.Oidc.UserInfoEndpoint, token)
	if err != nil {
		return nil, err
	}
	return userinfo, nil
}
