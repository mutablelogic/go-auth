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

package cmd

import (
	"os"
	"path/filepath"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ClientEndpoint returns the endpoint of the command's HTTP flags, and its
// client options, as the command's ClientEndpoint does, with the token
// which signing in kept for the endpoint, when it hasn't expired
func ClientEndpoint(ctx server.Cmd) (string, []client.ClientOpt, error) {
	endpoint, opts, err := ctx.ClientEndpoint()
	if err != nil {
		return "", nil, err
	}
	return endpoint, append(opts, TokenOpts(ctx, endpoint)...), nil
}

// TokenOpts returns the client option of the token which signing in kept
// for the endpoint, or none, when there isn't one, or it's expired
func TokenOpts(ctx server.Cmd, endpoint string) []client.ClientOpt {
	tokens, err := tokens(ctx)
	if err != nil {
		return nil
	}
	token, err := tokens.Get(endpoint)
	if err != nil || !token.Valid() {
		return nil
	}
	return []client.ClientOpt{client.OptReqToken(client.Token{Scheme: client.Bearer, Value: token.AccessToken})}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// tokens are the tokens signing in keeps, in the user's configuration
// directory, by the command's name
func tokens(ctx server.Cmd) (*httpclient.Tokens, error) {
	config, err := os.UserConfigDir()
	if err != nil {
		return nil, err
	}
	return httpclient.NewTokens(filepath.Join(config, ctx.Name(), "tokens.json"))
}
