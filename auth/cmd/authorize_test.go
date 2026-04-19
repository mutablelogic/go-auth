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
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	// Packages
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	clientpkg "github.com/mutablelogic/go-client"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	metric "go.opentelemetry.io/otel/metric"
	trace "go.opentelemetry.io/otel/trace"
	oauth2 "golang.org/x/oauth2"
)

type fakeCmd struct {
	ctx      context.Context
	endpoint string
	store    map[string]any
	mu       sync.Mutex
	logger   *slog.Logger
}

func newFakeCmd(endpoint string) *fakeCmd {
	return &fakeCmd{
		ctx:      context.Background(),
		endpoint: endpoint,
		store:    make(map[string]any),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (f *fakeCmd) Name() string             { return "test" }
func (f *fakeCmd) Description() string      { return "test" }
func (f *fakeCmd) Version() string          { return "test" }
func (f *fakeCmd) Context() context.Context { return f.ctx }
func (f *fakeCmd) Logger() *slog.Logger     { return f.logger }
func (f *fakeCmd) Tracer() trace.Tracer     { return nil }
func (f *fakeCmd) Meter() metric.Meter      { return nil }
func (f *fakeCmd) ClientEndpoint() (string, []clientpkg.ClientOpt, error) {
	return f.endpoint, nil, nil
}
func (f *fakeCmd) Get(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.store[key]
}
func (f *fakeCmd) GetString(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, _ := f.store[key].(string)
	return value
}
func (f *fakeCmd) Set(key string, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if value == nil {
		delete(f.store, key)
	} else {
		f.store[key] = value
	}
	return nil
}
func (f *fakeCmd) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.store))
	for key := range f.store {
		keys = append(keys, key)
	}
	return keys
}
func (f *fakeCmd) IsTerm() int                { return 0 }
func (f *fakeCmd) IsDebug() bool              { return false }
func (f *fakeCmd) HTTPAddr() string           { return "" }
func (f *fakeCmd) HTTPPrefix() string         { return "" }
func (f *fakeCmd) HTTPTimeout() time.Duration { return 0 }

func TestStoreTokenStoresProviderMetadata(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := newFakeCmd("https://resource.example.test/api")
	token := &oauth2.Token{
		AccessToken:  "access",
		RefreshToken: "refresh",
		TokenType:    "Bearer",
		Expiry:       time.Now().Add(time.Hour),
		ExpiresIn:    3600,
	}

	require.NoError(storeToken(ctx, ctx.endpoint, "https://auth.example.test/api", "google", token))
	assert.Equal("google", storedProvider(ctx, ctx.endpoint))

	stored, err := storedToken(ctx, ctx.endpoint)
	require.NoError(err)
	require.NotNil(stored)
	assert.Equal(int64(0), stored.ExpiresIn)
}

func TestCanReuseStoredTokenForStoredProvider(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := newFakeCmd("https://resource.example.test/api")
	require.NoError(storeToken(ctx, ctx.endpoint, "https://auth.example.test/api", "google", &oauth2.Token{
		AccessToken: "access",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}))

	reuse, err := canReuseStoredTokenForProvider(ctx, nil, ctx.endpoint, "google")
	require.NoError(err)
	assert.True(reuse)

	reuse, err = canReuseStoredTokenForProvider(ctx, nil, ctx.endpoint, "local")
	require.NoError(err)
	assert.False(reuse)
}

func TestCanReuseStoredTokenForLegacyNonLocalProvider(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := newFakeCmd("https://resource.example.test/api")
	require.NoError(storeToken(ctx, ctx.endpoint, "https://auth.example.test/api", "", &oauth2.Token{
		AccessToken: "access",
		TokenType:   "Bearer",
		Expiry:      time.Now().Add(time.Hour),
	}))
	require.NoError(ctx.Set(providerStoreKey(ctx.endpoint), nil))

	reuse, err := canReuseStoredTokenForProvider(ctx, nil, ctx.endpoint, "google")
	require.NoError(err)
	assert.True(reuse)
	assert.Equal("google", storedProvider(ctx, ctx.endpoint))
}

func TestAuthorizationScopesUsesProtectedResourceScopesForOAuth(t *testing.T) {
	assert := assert.New(t)

	cmd := AuthorizeCommand{}
	meta := &httpclient.Config{
		ProtectedResourceMetadata: oidc.ProtectedResourceMetadata{
			ScopesSupported: []string{"repo", "read:user"},
		},
	}
	serverMeta := &httpclient.ServerMetadata{
		Issuer: "https://github.com/login/oauth",
		OAuth: oidc.OAuthConfiguration{
			BaseConfiguration: oidc.BaseConfiguration{
				AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
				TokenEndpoint:         "https://github.com/login/oauth/access_token",
			},
		},
	}

	assert.Equal([]string{"repo", "read:user"}, cmd.authorizationScopes(meta, serverMeta))
}

func TestAuthorizationServerAndClientCredentialsRequiresClientIDForExternalOAuth(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := newFakeCmd("https://api.githubcopilot.com/mcp/")
	cmd := AuthorizeCommand{Endpoint: ctx.endpoint}
	meta := &httpclient.Config{
		ProtectedResourceMetadata: oidc.ProtectedResourceMetadata{
			Resource:             ctx.endpoint,
			ScopesSupported:      []string{"repo"},
			AuthorizationServers: []string{"https://github.com/login/oauth"},
		},
		AuthorizationServers: []httpclient.ServerMetadata{{
			Issuer: "https://github.com/login/oauth",
			OAuth: oidc.OAuthConfiguration{
				BaseConfiguration: oidc.BaseConfiguration{
					Issuer:                "https://github.com/login/oauth",
					AuthorizationEndpoint: "https://github.com/login/oauth/authorize",
					TokenEndpoint:         "https://github.com/login/oauth/access_token",
				},
			},
		}},
	}

	serverMeta, clientID, clientSecret, err := cmd.authorizationServerAndClientCredentials(ctx, nil, meta, "http://localhost/")
	require.Error(err)
	assert.Nil(serverMeta)
	assert.Empty(clientID)
	assert.Empty(clientSecret)
	assert.EqualError(err, `client ID is required for authorization server "https://github.com/login/oauth"`)
}

func TestAuthorizationServerAndClientCredentialsAllowsInternalCodeExchangeWithoutClientID(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	ctx := newFakeCmd("http://localhost:8084/api/resource")
	cmd := AuthorizeCommand{Endpoint: ctx.endpoint}
	meta := &httpclient.Config{
		ProtectedResourceMetadata: oidc.ProtectedResourceMetadata{
			Resource: ctx.endpoint,
		},
		AuthorizationServers: []httpclient.ServerMetadata{{
			Issuer: "http://localhost:8084/api",
			Oidc: oidc.OIDCConfiguration{
				BaseConfiguration: oidc.BaseConfiguration{
					Issuer:                "http://localhost:8084/api",
					AuthorizationEndpoint: "http://localhost:8084/api/auth/authorize",
					TokenEndpoint:         "http://localhost:8084/api/auth/code",
				},
			},
		}},
	}

	serverMeta, clientID, clientSecret, err := cmd.authorizationServerAndClientCredentials(ctx, nil, meta, "http://localhost/")
	require.NoError(err)
	require.NotNil(serverMeta)
	assert.Equal("http://localhost:8084/api", serverMeta.Issuer)
	assert.Empty(clientID)
	assert.Empty(clientSecret)
}
