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
	"strings"

	// Packages

	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RevokeCommand struct {
	Endpoint     string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
	ClientID     string `name:"client-id" help:"OAuth client ID. Defaults to the stored client ID for the issuer."`
	ClientSecret string `name:"client-secret" help:"OAuth client secret. Defaults to the stored client secret for the issuer when required by the provider."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *RevokeCommand) Run(ctx server.Cmd) error {
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

	issuer := strings.TrimSpace(ctx.GetString(issuerStoreKey(cmd.Endpoint)))
	clientID := strings.TrimSpace(cmd.ClientID)
	clientSecret := strings.TrimSpace(cmd.ClientSecret)
	if clientID == "" && issuer != "" {
		clientID = strings.TrimSpace(ctx.GetString(clientIDStoreKey(nil, issuer)))
	}
	if clientSecret == "" && issuer != "" {
		clientSecret = strings.TrimSpace(ctx.GetString(clientSecretStoreKey(nil, issuer)))
	}

	meta, err := discoverAuthMetadata(ctx, authClient, cmd.Endpoint)
	if err != nil {
		return err
	}
	serverMeta, err := meta.AuthorizationServerForFlow()
	if err != nil {
		return err
	}
	config, err := serverMeta.AuthorizationCodeConfig()
	if err != nil {
		return err
	}
	if issuer == "" {
		issuer = strings.TrimSpace(config.Issuer)
		if issuer == "" {
			issuer = strings.TrimSpace(serverMeta.Issuer)
		}
	}
	if endpoint := strings.TrimSpace(config.RevocationEndpoint); endpoint != "" {
		if err := authClient.RevokeToken(ctx.Context(), endpoint, token, clientID, clientSecret); err != nil {
			return err
		}
	}
	return deleteStoredToken(ctx, cmd.Endpoint, issuer)
}
