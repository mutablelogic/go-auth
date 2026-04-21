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
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type RevokeCommand struct {
	Endpoint string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
}

func (cmd RevokeCommand) String() string {
	return types.Stringify(cmd)
}

func (cmd RevokeCommand) RedactedString() string {
	return types.Stringify(cmd)
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *RevokeCommand) Run(globals server.Cmd) (err error) {
	return withAuth(globals, "RevokeCommand", types.Stringify(cmd), func(ctx context.Context, authclient *auth.Client) error {
		// Get the endpoint, defaulting to the global HTTP client endpoint
		if endpoint, err := endpoint(globals, authclient, cmd.Endpoint, ""); err != nil {
			return err
		} else {
			cmd.Endpoint = endpoint.String()
		}

		// Get the token
		token, err := storedToken(globals, cmd.Endpoint)
		if err != nil {
			return err
		}
		if token == nil {
			return fmt.Errorf("no stored token for endpoint %q", cmd.Endpoint)
		}

		issuer := strings.TrimSpace(globals.GetString(issuerStoreKey(cmd.Endpoint)))
		clientID := ""
		clientSecret := ""
		if issuer != "" {
			clientID = strings.TrimSpace(globals.GetString(clientIDStoreKey(nil, issuer)))
			clientSecret = strings.TrimSpace(globals.GetString(clientSecretStoreKey(nil, issuer)))
		}

		meta, err := discoverAuthMetadata(globals, ctx, authclient, cmd.Endpoint)
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
			if err := authclient.RevokeToken(ctx, endpoint, token, clientID, clientSecret); err != nil {
				return err
			}
		}
		return deleteStoredToken(globals, cmd.Endpoint, issuer)
	})
}
