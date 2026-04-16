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
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	oidc "github.com/mutablelogic/go-auth/pkg/oidc"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestResourceMetadataCandidates(t *testing.T) {
	t.Run("NestedResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://example.com/.well-known/oauth-protected-resource/api/user/123",
			"https://example.com/.well-known/oauth-protected-resource/api/user",
			"https://example.com/.well-known/oauth-protected-resource/api",
			"https://example.com/.well-known/oauth-protected-resource",
		}, progressiveMetadataCandidates("https://example.com/api/user/123", oidc.ProtectedResourcePath))
	})

	t.Run("RootResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://example.com/.well-known/oauth-protected-resource",
		}, progressiveMetadataCandidates("https://example.com/", oidc.ProtectedResourcePath))
	})

	t.Run("QueryAndFragmentIgnored", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://example.com/.well-known/oauth-protected-resource/api",
			"https://example.com/.well-known/oauth-protected-resource",
		}, progressiveMetadataCandidates("https://example.com/api?view=full#fragment", oidc.ProtectedResourcePath))
	})

	t.Run("InvalidResource", func(t *testing.T) {
		assert.Nil(t, progressiveMetadataCandidates("/relative/path", oidc.ProtectedResourcePath))
	})
}

func TestOIDCMetadataCandidates(t *testing.T) {
	t.Run("RootIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://accounts.google.com/.well-known/openid-configuration",
		}, metadataCandidates("https://accounts.google.com/", oidc.ConfigPath, oidc.ConfigURL("https://accounts.google.com/")))
	})

	t.Run("PathIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://issuer.example.com/auth/.well-known/openid-configuration",
			"https://issuer.example.com/.well-known/openid-configuration/auth",
			"https://issuer.example.com/.well-known/openid-configuration",
		}, metadataCandidates("https://issuer.example.com/auth/", oidc.ConfigPath, oidc.ConfigURL("https://issuer.example.com/auth/")))
	})

	t.Run("PathResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://mcp.atlassian.com/v1/sse/.well-known/openid-configuration",
			"https://mcp.atlassian.com/.well-known/openid-configuration/v1/sse",
			"https://mcp.atlassian.com/.well-known/openid-configuration",
		}, metadataCandidates("https://mcp.atlassian.com/v1/sse", oidc.ConfigPath, oidc.ConfigURL("https://mcp.atlassian.com/v1/sse")))
	})

	t.Run("InvalidIssuer", func(t *testing.T) {
		assert.Nil(t, metadataCandidates("/relative/path", oidc.ConfigPath, oidc.ConfigURL("/relative/path")))
	})
}

func TestOAuthMetadataCandidates(t *testing.T) {
	t.Run("RootIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://accounts.google.com/.well-known/oauth-authorization-server",
		}, metadataCandidates("https://accounts.google.com/", oidc.OAuthConfigPath, oidc.OAuthConfigURL("https://accounts.google.com/")))
	})

	t.Run("PathIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://issuer.example.com/auth/.well-known/oauth-authorization-server",
			"https://issuer.example.com/.well-known/oauth-authorization-server/auth",
			"https://issuer.example.com/.well-known/oauth-authorization-server",
		}, metadataCandidates("https://issuer.example.com/auth/", oidc.OAuthConfigPath, oidc.OAuthConfigURL("https://issuer.example.com/auth/")))
	})

	t.Run("PathResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://mcp.atlassian.com/v1/sse/.well-known/oauth-authorization-server",
			"https://mcp.atlassian.com/.well-known/oauth-authorization-server/v1/sse",
			"https://mcp.atlassian.com/.well-known/oauth-authorization-server",
		}, metadataCandidates("https://mcp.atlassian.com/v1/sse", oidc.OAuthConfigPath, oidc.OAuthConfigURL("https://mcp.atlassian.com/v1/sse")))
	})

	t.Run("InvalidIssuer", func(t *testing.T) {
		assert.Nil(t, metadataCandidates("/relative/path", oidc.OAuthConfigPath, oidc.OAuthConfigURL("/relative/path")))
	})
}

func TestAuthorizationURIIssuerCandidates(t *testing.T) {
	t.Run("AuthorizePath", func(t *testing.T) {
		authErr := &AuthError{Values: url.Values{"authorization_uri": {"https://auth.example.test/authorize"}}}
		assert.Equal(t, []string{"https://auth.example.test"}, authorizationURIIssuerCandidates(authErr))
	})

	t.Run("OAuth2AuthorizePath", func(t *testing.T) {
		authErr := &AuthError{Values: url.Values{"authorization_uri": {"https://auth.example.test/oauth2/authorize"}}}
		assert.Equal(t, []string{"https://auth.example.test"}, authorizationURIIssuerCandidates(authErr))
	})

	t.Run("GoogleStylePath", func(t *testing.T) {
		authErr := &AuthError{Values: url.Values{"authorization_uri": {"https://accounts.example.test/o/oauth2/v2/auth"}}}
		assert.Equal(t, []string{"https://accounts.example.test"}, authorizationURIIssuerCandidates(authErr))
	})

	t.Run("Invalid", func(t *testing.T) {
		authErr := &AuthError{Values: url.Values{"authorization_uri": {"not-a-url"}}}
		assert.Nil(t, authorizationURIIssuerCandidates(authErr))
	})
}

func TestAuthServerCandidates(t *testing.T) {
	authErr := &AuthError{Values: url.Values{
		"authorization_uri":        {"https://auth.example.test/authorize"},
		"realm":                    {"https://realm.example.test"},
		"authorization_server_uri": {"https://issuer.example.test"},
	}}
	assert.Equal(t, []string{
		"https://issuer.example.test",
		"https://auth.example.test",
		"https://realm.example.test",
	}, authServerCandidates(authErr))
}

func TestInteroperabilityIssuerCandidates(t *testing.T) {
	t.Run("AtlassianMcp", func(t *testing.T) {
		assert.Equal(t, []string{"https://auth.atlassian.com"}, interoperabilityIssuerCandidates("https://mcp.atlassian.com/v1/sse"))
	})

	t.Run("OtherHost", func(t *testing.T) {
		assert.Nil(t, interoperabilityIssuerCandidates("https://api.example.test/resource"))
	})
}

func TestServerMetadataAuthorizationCodeConfigRequiresTokenEndpoint(t *testing.T) {
	_, err := (&ServerMetadata{Oidc: oidc.OIDCConfiguration{BaseConfiguration: oidc.BaseConfiguration{AuthorizationEndpoint: "https://issuer.example.test/authorize"}}}).AuthorizationCodeConfig()
	require.EqualError(t, err, "no authorization code flow is advertised")
}

func TestDiscoverFromIssuerFallsBackToOAuthWhenOIDCIncomplete(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":   srv.URL,
				"jwks_uri": srv.URL + "/jwks",
			}))
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                                srv.URL,
				"authorization_endpoint":                srv.URL + "/authorize",
				"token_endpoint":                        srv.URL + "/token",
				"token_endpoint_auth_methods_supported": []string{"client_secret_post"},
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := New(srv.URL)
	require.NoError(t, err)

	meta, err := client.discoverFromIssuer(context.Background(), srv.URL)
	require.NoError(t, err)

	config, err := meta.AuthorizationCodeConfig()
	require.NoError(t, err)
	assert.Equal(t, srv.URL+"/authorize", config.AuthorizationEndpoint)
	assert.Equal(t, srv.URL+"/token", config.TokenEndpoint)
	assert.Equal(t, []string{"client_secret_post"}, config.TokenEndpointAuthMethods)
	assert.False(t, config.NonceSupported)
}

func TestDiscoverFromIssuerSynthesizesGitHubLegacyMetadata(t *testing.T) {
	_, err := (&ServerMetadata{Issuer: "https://github.com/login/oauth"}).AuthorizationCodeConfig()
	require.EqualError(t, err, "no authorization code flow is advertised")

	serverMeta := &ServerMetadata{Issuer: "https://github.com/login/oauth"}
	require.True(t, serverMeta.applyLegacyAuthorizationCodeFallback())

	config, err := serverMeta.AuthorizationCodeConfig()
	require.NoError(t, err)
	assert.Equal(t, "https://github.com/login/oauth/authorize", config.AuthorizationEndpoint)
	assert.Equal(t, "https://github.com/login/oauth/access_token", config.TokenEndpoint)
	assert.Equal(t, []string{"client_secret_post"}, config.TokenEndpointAuthMethods)
	assert.False(t, config.NonceSupported)
}

func TestDiscoverWithErrorMergesResourceMetadataAndChallengeCandidates(t *testing.T) {
	resourceIssuer := "https://resource-only.example.test/oauth"
	var authSrv *httptest.Server
	authSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":   authSrv.URL,
				"jwks_uri": authSrv.URL + "/jwks",
			}))
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                 authSrv.URL,
				"authorization_endpoint": authSrv.URL + "/authorize",
				"token_endpoint":         authSrv.URL + "/token",
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer authSrv.Close()

	var resourceSrv *httptest.Server
	resourceSrv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/.well-known/oauth-protected-resource/mcp" {
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"resource":              resourceSrv.URL + "/mcp",
				"authorization_servers": []string{resourceIssuer},
			}))
			return
		}
		http.NotFound(w, r)
	}))
	defer resourceSrv.Close()

	client, err := New(resourceSrv.URL)
	require.NoError(t, err)

	authErr := &AuthError{Scheme: "Bearer", Values: url.Values{
		"resource_metadata": {resourceSrv.URL + "/.well-known/oauth-protected-resource/mcp"},
		"authorization_uri": {authSrv.URL + "/authorize"},
	}}

	config, err := client.DiscoverWithError(context.Background(), authErr)
	require.NoError(t, err)

	flowConfig, err := config.AuthorizationCodeConfig()
	require.NoError(t, err)
	assert.Equal(t, authSrv.URL+"/authorize", flowConfig.AuthorizationEndpoint)
	assert.Equal(t, authSrv.URL+"/token", flowConfig.TokenEndpoint)
	require.Len(t, config.ProtectedResourceMetadata.AuthorizationServers, 1)
	assert.Equal(t, resourceIssuer, config.ProtectedResourceMetadata.AuthorizationServers[0])
	require.Len(t, config.AuthorizationServers, 1)
	assert.Equal(t, authSrv.URL, config.AuthorizationServers[0].Issuer)
}

func TestDiscoverWithErrorFallsBackToEndpointWhenChallengeHasNoHints(t *testing.T) {
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			w.Header().Set("Content-Type", "application/json")
			require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
				"issuer":                           srv.URL,
				"authorization_endpoint":           srv.URL + "/authorize",
				"token_endpoint":                   srv.URL + "/token",
				"response_types_supported":         []string{"code"},
				"grant_types_supported":            []string{"authorization_code", "refresh_token"},
				"code_challenge_methods_supported": []string{"S256"},
			}))
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()

	client, err := New(srv.URL + "/sse")
	require.NoError(t, err)

	authErr := &AuthError{Scheme: "Bearer", Values: url.Values{
		"realm":             {"OAuth"},
		"error":             {"invalid_token"},
		"error_description": {"Missing or invalid access token"},
	}}

	config, err := client.DiscoverWithError(context.Background(), authErr)
	require.NoError(t, err)
	require.Len(t, config.AuthorizationServers, 1)
	assert.Equal(t, srv.URL, config.AuthorizationServers[0].Issuer)

	flowConfig, err := config.AuthorizationCodeConfig()
	require.NoError(t, err)
	assert.Equal(t, srv.URL+"/authorize", flowConfig.AuthorizationEndpoint)
	assert.Equal(t, srv.URL+"/token", flowConfig.TokenEndpoint)
	assert.Equal(t, []string{"S256"}, flowConfig.CodeChallengeMethods)
}

func TestDiscoverWithErrorWrapsResourceMetadataFetchError(t *testing.T) {
	resourceSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer resourceSrv.Close()

	client, err := New(resourceSrv.URL)
	require.NoError(t, err)

	endpoint := resourceSrv.URL + "/.well-known/oauth-protected-resource/mcp"
	authErr := &AuthError{Scheme: "Bearer", Values: url.Values{
		"resource_metadata": {endpoint},
	}}

	_, err = client.DiscoverWithError(context.Background(), authErr)
	require.Error(t, err)
	require.ErrorContains(t, err, endpoint)
	require.ErrorContains(t, err, "fetch resource metadata")
}
