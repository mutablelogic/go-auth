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

	assert "github.com/stretchr/testify/assert"
)

func TestResourceMetadataCandidates(t *testing.T) {
	t.Run("NestedResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://example.com/.well-known/oauth-protected-resource/api/user/123",
			"https://example.com/.well-known/oauth-protected-resource/api/user",
			"https://example.com/.well-known/oauth-protected-resource/api",
			"https://example.com/.well-known/oauth-protected-resource",
		}, resourceMetadataCandidates("https://example.com/api/user/123"))
	})

	t.Run("RootResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://example.com/.well-known/oauth-protected-resource",
		}, resourceMetadataCandidates("https://example.com/"))
	})

	t.Run("QueryAndFragmentIgnored", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://example.com/.well-known/oauth-protected-resource/api",
			"https://example.com/.well-known/oauth-protected-resource",
		}, resourceMetadataCandidates("https://example.com/api?view=full#fragment"))
	})

	t.Run("InvalidResource", func(t *testing.T) {
		assert.Nil(t, resourceMetadataCandidates("/relative/path"))
	})
}

func TestOIDCMetadataCandidates(t *testing.T) {
	t.Run("RootIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://accounts.google.com/.well-known/openid-configuration",
		}, oidcMetadataCandidates("https://accounts.google.com/"))
	})

	t.Run("PathIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://issuer.example.com/auth/.well-known/openid-configuration",
			"https://issuer.example.com/.well-known/openid-configuration/auth",
			"https://issuer.example.com/.well-known/openid-configuration",
		}, oidcMetadataCandidates("https://issuer.example.com/auth/"))
	})

	t.Run("PathResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://mcp.atlassian.com/v1/sse/.well-known/openid-configuration",
			"https://mcp.atlassian.com/.well-known/openid-configuration/v1/sse",
			"https://mcp.atlassian.com/.well-known/openid-configuration",
		}, oidcMetadataCandidates("https://mcp.atlassian.com/v1/sse"))
	})

	t.Run("InvalidIssuer", func(t *testing.T) {
		assert.Nil(t, oidcMetadataCandidates("/relative/path"))
	})
}

func TestOAuthMetadataCandidates(t *testing.T) {
	t.Run("RootIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://accounts.google.com/.well-known/oauth-authorization-server",
		}, oauthMetadataCandidates("https://accounts.google.com/"))
	})

	t.Run("PathIssuer", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://issuer.example.com/auth/.well-known/oauth-authorization-server",
			"https://issuer.example.com/.well-known/oauth-authorization-server/auth",
			"https://issuer.example.com/.well-known/oauth-authorization-server",
		}, oauthMetadataCandidates("https://issuer.example.com/auth/"))
	})

	t.Run("PathResource", func(t *testing.T) {
		assert.Equal(t, []string{
			"https://mcp.atlassian.com/v1/sse/.well-known/oauth-authorization-server",
			"https://mcp.atlassian.com/.well-known/oauth-authorization-server/v1/sse",
			"https://mcp.atlassian.com/.well-known/oauth-authorization-server",
		}, oauthMetadataCandidates("https://mcp.atlassian.com/v1/sse"))
	})

	t.Run("InvalidIssuer", func(t *testing.T) {
		assert.Nil(t, oauthMetadataCandidates("/relative/path"))
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
