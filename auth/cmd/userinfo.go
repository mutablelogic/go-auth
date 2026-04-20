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
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httpclient"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
	oauth2 "golang.org/x/oauth2"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserInfoCommand struct {
	Endpoint string `arg:"" optional:"" name:"endpoint" help:"Protected resource endpoint. Defaults to the stored endpoint or the global HTTP client endpoint."`
}

func (cmd UserInfoCommand) String() string {
	return types.Stringify(cmd)
}

func (cmd UserInfoCommand) RedactedString() string {
	return types.Stringify(cmd)
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *UserInfoCommand) Run(ctx server.Cmd) (err error) {
	spanctx, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), "UserInfoCommand",
		attribute.String("cmd", cmd.RedactedString()),
	)
	defer func() { endSpan(err) }()

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

	meta, err := discoverAuthMetadata(ctx, spanctx, authClient, cmd.Endpoint)
	if err != nil {
		return err
	}

	// Get the token
	token, err := storedToken(ctx, cmd.Endpoint)
	if err != nil {
		return err
	}
	if token == nil {
		return fmt.Errorf("no stored token for endpoint %q", cmd.Endpoint)
	}
	if !token.Valid() {
		if token, err = refreshStoredTokenWithMetadata(ctx, spanctx, authClient, meta, cmd.Endpoint); err != nil {
			return err
		}
	}

	// Get the user info
	userinfo, err := userInfoForEndpointWithMetadata(ctx, spanctx, authClient, meta, cmd.Endpoint, token)
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

func userInfoForEndpoint(ctx server.Cmd, spanctx context.Context, authClient *auth.Client, endpoint string, token *oauth2.Token) (*oidc.UserInfo, error) {
	if spanctx == nil && ctx != nil {
		spanctx = ctx.Context()
	}

	meta, err := discoverAuthMetadata(ctx, spanctx, authClient, endpoint)
	if err != nil {
		return nil, err
	}

	return userInfoForEndpointWithMetadata(ctx, spanctx, authClient, meta, endpoint, token)
}

func userInfoForEndpointWithMetadata(ctx server.Cmd, spanctx context.Context, authClient *auth.Client, meta *auth.Config, endpoint string, token *oauth2.Token) (*oidc.UserInfo, error) {
	if spanctx == nil && ctx != nil {
		spanctx = ctx.Context()
	}

	endpoint = strings.TrimSpace(endpoint)
	if token == nil {
		return nil, fmt.Errorf("token is required")
	}
	serverMeta, err := meta.AuthorizationServerForUserInfo()
	if err != nil {
		return nil, err
	}
	return authClient.UserInfo(spanctx, serverMeta.Oidc.UserInfoEndpoint, token)
}
