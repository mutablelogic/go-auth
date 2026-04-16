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
	"net/url"
	"testing"

	// Packages
	authclient "github.com/mutablelogic/go-auth/pkg/httpclient/auth"
	oidc "github.com/mutablelogic/go-auth/pkg/oidc"
	require "github.com/stretchr/testify/require"
)

func TestAuthorizationServerAndClientCredentialsAllowsProviderFlowWithoutClientID(t *testing.T) {
	cmd := &AuthorizeCommand{}
	meta := &authclient.Config{AuthorizationServers: []authclient.ServerMetadata{{
		Issuer: "http://localhost:8084/api",
		Oidc: oidc.OIDCConfiguration{BaseConfiguration: oidc.BaseConfiguration{
			Issuer:                "http://localhost:8084/api",
			AuthorizationEndpoint: "http://localhost:8084/api/auth/authorize",
			TokenEndpoint:         "http://localhost:8084/api/auth/code",
		}},
	}}}

	serverMeta, clientID, clientSecret, err := cmd.authorizationServerAndClientCredentials(nil, nil, meta, "http://localhost:12345/")
	require.NoError(t, err)
	require.NotNil(t, serverMeta)
	require.Equal(t, "http://localhost:8084/api", serverMeta.Issuer)
	require.Empty(t, clientID)
	require.Empty(t, clientSecret)
}

func TestAuthorizationServerAndClientCredentialsStillFailsWithoutFlowOrRegistration(t *testing.T) {
	cmd := &AuthorizeCommand{}
	meta := &authclient.Config{AuthorizationServers: []authclient.ServerMetadata{{Issuer: "http://localhost:8084/api"}}}

	serverMeta, clientID, clientSecret, err := cmd.authorizationServerAndClientCredentials(nil, nil, meta, "http://localhost:12345/")
	require.Nil(t, serverMeta)
	require.Empty(t, clientID)
	require.Empty(t, clientSecret)
	require.EqualError(t, err, "client ID is required or dynamic registration must succeed: no registration endpoint is advertised")
}

func TestAuthorizationURLWithHints(t *testing.T) {
	t.Run("ProviderHint", func(t *testing.T) {
		rawURL, err := authorizationURLWithHints("http://localhost:8084/api/auth/authorize?state=test", "local")
		require.NoError(t, err)

		uri, err := url.Parse(rawURL)
		require.NoError(t, err)
		require.Equal(t, "local", uri.Query().Get("provider"))
		require.Equal(t, "test", uri.Query().Get("state"))
	})

	t.Run("EmptyProviderHint", func(t *testing.T) {
		rawURL, err := authorizationURLWithHints("http://localhost:8084/api/auth/authorize?state=test", "")
		require.NoError(t, err)

		uri, err := url.Parse(rawURL)
		require.NoError(t, err)
		require.Empty(t, uri.Query().Get("provider"))
		require.Equal(t, "test", uri.Query().Get("state"))
	})
}
