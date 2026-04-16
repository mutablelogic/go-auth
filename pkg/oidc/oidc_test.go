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

package oidc_test

import (
	"fmt"
	"net/url"
	"testing"

	// Packages
	authcrypto "github.com/mutablelogic/go-auth/pkg/crypto"
	oidc "github.com/mutablelogic/go-auth/pkg/oidc"
	jwt "github.com/golang-jwt/jwt/v5"
	jwk "github.com/lestrrat-go/jwx/v2/jwk"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestSign(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	claims := jwt.MapClaims{
		"iss": "https://issuer.example.com",
		"sub": "alice",
	}

	token, err := oidc.SignToken(key, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		assert.Equal(t, oidc.SigningAlgorithm, token.Method.Alg())
		assert.Equal(t, oidc.KeyID, token.Header["kid"])
		return &key.PublicKey, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
	assert.Equal(t, oidc.KeyID, parsed.Header["kid"])
}

func TestSignWithoutKeyUsesNoneAlgorithm(t *testing.T) {
	token, err := oidc.SignToken(nil, jwt.MapClaims{"iss": "https://issuer.example.com"})
	require.NoError(t, err)
	assert.NotEmpty(t, token)

	parsed, err := jwt.Parse(token, func(token *jwt.Token) (any, error) {
		assert.Equal(t, jwt.SigningMethodNone.Alg(), token.Method.Alg())
		_, exists := token.Header["kid"]
		assert.False(t, exists)
		return jwt.UnsafeAllowNoneSignatureType, nil
	})
	require.NoError(t, err)
	assert.True(t, parsed.Valid)
}

func TestIssueToken(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	claims := jwt.MapClaims{"sub": "alice"}
	claims["iss"] = "https://issuer.example.com"
	token, err := oidc.IssueToken(key, claims)
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, "https://issuer.example.com", claims["iss"])
	assert.Contains(t, claims, "iat")
	assert.Contains(t, claims, "nbf")
	assert.Contains(t, claims, "exp")
}

func TestIssueTokenRequiresIssuer(t *testing.T) {
	_, err := oidc.IssueToken(nil, jwt.MapClaims{"sub": "alice"})
	require.Error(t, err)
}

func TestSignTokenRequiresClaims(t *testing.T) {
	_, err := oidc.SignToken(nil, nil)
	require.Error(t, err)
}

func TestPublicJWKSet(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	jwks, err := oidc.PublicJWKSet(key)
	require.NoError(t, err)

	require.Equal(t, 1, jwks.Len())
	entry, ok := jwks.LookupKeyID(oidc.KeyID)
	require.True(t, ok)

	alg, ok := entry.Get(jwk.AlgorithmKey)
	require.True(t, ok)
	use, ok := entry.Get(jwk.KeyUsageKey)
	require.True(t, ok)
	kty, ok := entry.Get(jwk.KeyTypeKey)
	require.True(t, ok)
	n, ok := entry.Get("n")
	require.True(t, ok)
	e, ok := entry.Get("e")
	require.True(t, ok)

	assert.Equal(t, oidc.SigningAlgorithm, fmt.Sprint(alg))
	assert.Equal(t, "sig", fmt.Sprint(use))
	assert.Equal(t, "RSA", fmt.Sprint(kty))
	assert.NotEmpty(t, n)
	assert.NotEmpty(t, e)
}

func TestConfigURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/.well-known/openid-configuration",
		oidc.ConfigURL("https://issuer.example.com/api/"),
	)
}

func TestOAuthConfigURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/.well-known/oauth-authorization-server",
		oidc.OAuthConfigURL("https://issuer.example.com/api/"),
	)
}

func TestJWKSURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/.well-known/jwks.json",
		oidc.JWKSURL("https://issuer.example.com/api/"),
	)
}

func TestAuthorizationURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/auth/authorize",
		oidc.AuthorizationURL("https://issuer.example.com/api/"),
	)
}

func TestAuthCodeURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/auth/code",
		oidc.AuthCodeURL("https://issuer.example.com/api/"),
	)
}

func TestAuthRevokeURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/auth/revoke",
		oidc.AuthRevokeURL("https://issuer.example.com/api/"),
	)
}

func TestUserInfoURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/auth/userinfo",
		oidc.UserInfoURL("https://issuer.example.com/api/"),
	)
}

func TestPreferredCodeChallengeMethod(t *testing.T) {
	assert.Equal(t, oidc.CodeChallengeMethodS256, oidc.PreferredCodeChallengeMethod([]string{"plain", "S256"}))
	assert.Equal(t, oidc.CodeChallengeMethodPlain, oidc.PreferredCodeChallengeMethod([]string{"plain"}))
	assert.Equal(t, "", oidc.PreferredCodeChallengeMethod(nil))
}

func TestNewCodeChallenge(t *testing.T) {
	verifier, challenge, err := oidc.NewCodeChallenge(oidc.CodeChallengeMethodS256)
	require.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.NotEmpty(t, challenge)
	assert.NotEqual(t, verifier, challenge)

	verifier, challenge, err = oidc.NewCodeChallenge(oidc.CodeChallengeMethodPlain)
	require.NoError(t, err)
	assert.NotEmpty(t, verifier)
	assert.Equal(t, verifier, challenge)
}

func TestAuthorizationCodeFlow(t *testing.T) {
	flow, err := oidc.NewAuthorizationCodeFlow(oidc.BaseConfiguration{
		Issuer:                oidc.GoogleIssuer,
		AuthorizationEndpoint: "https://accounts.example.test/o/oauth2/v2/auth",
		TokenEndpoint:         "https://accounts.example.test/token",
		CodeChallengeMethods:  []string{oidc.CodeChallengeMethodPlain, oidc.CodeChallengeMethodS256},
		NonceSupported:        true,
	}, "client-id", "http://127.0.0.1:8085/callback", oidc.DefaultOIDCAuthorizationScopes...)
	require.NoError(t, err)
	require.NotNil(t, flow)
	assert.Equal(t, oidc.GoogleIssuer, flow.Issuer)
	assert.Equal(t, oidc.ResponseTypeCode, flow.ResponseType)
	assert.Equal(t, oidc.CodeChallengeMethodS256, flow.CodeChallengeMethod)
	assert.NotEmpty(t, flow.State)
	assert.NotEmpty(t, flow.Nonce)
	assert.NotEmpty(t, flow.CodeVerifier)
	assert.NotEmpty(t, flow.CodeChallenge)
	assert.NotEmpty(t, flow.AuthorizationURL)

	uri, err := url.Parse(flow.AuthorizationURL)
	require.NoError(t, err)
	query := uri.Query()
	assert.Equal(t, "client-id", query.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:8085/callback", query.Get("redirect_uri"))
	assert.Equal(t, oidc.ResponseTypeCode, query.Get("response_type"))
	assert.Equal(t, flow.State, query.Get("state"))
	assert.Equal(t, flow.Nonce, query.Get("nonce"))
	assert.Equal(t, flow.CodeChallenge, query.Get("code_challenge"))
	assert.Equal(t, oidc.CodeChallengeMethodS256, query.Get("code_challenge_method"))
	assert.Equal(t, "openid email profile", query.Get("scope"))
}

func TestAuthorizationCodeFlowWithoutNonce(t *testing.T) {
	flow, err := oidc.NewAuthorizationCodeFlow(oidc.BaseConfiguration{
		Issuer:                "https://oauth.example.test",
		AuthorizationEndpoint: "https://oauth.example.test/authorize",
		TokenEndpoint:         "https://oauth.example.test/token",
		CodeChallengeMethods:  []string{oidc.CodeChallengeMethodS256},
	}, "client-id", "http://127.0.0.1:8085/callback", "projects:read")
	require.NoError(t, err)
	require.NotNil(t, flow)
	assert.Empty(t, flow.Nonce)

	uri, err := url.Parse(flow.AuthorizationURL)
	require.NoError(t, err)
	query := uri.Query()
	assert.Empty(t, query.Get("nonce"))
	assert.Equal(t, "projects:read", query.Get("scope"))
}

func TestAuthorizationCodeFlowWithoutClientID(t *testing.T) {
	flow, err := oidc.NewAuthorizationCodeFlow(oidc.BaseConfiguration{
		Issuer:                "https://auth.example.test",
		AuthorizationEndpoint: "https://auth.example.test/authorize",
		TokenEndpoint:         "https://auth.example.test/token",
		CodeChallengeMethods:  []string{oidc.CodeChallengeMethodS256},
	}, "", "http://127.0.0.1:8085/callback", oidc.DefaultOIDCAuthorizationScopes...)
	require.NoError(t, err)
	require.NotNil(t, flow)
	assert.Empty(t, flow.ClientID)

	uri, err := url.Parse(flow.AuthorizationURL)
	require.NoError(t, err)
	query := uri.Query()
	assert.Empty(t, query.Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:8085/callback", query.Get("redirect_uri"))
	assert.Equal(t, oidc.ResponseTypeCode, query.Get("response_type"))
	assert.Equal(t, "openid email profile", query.Get("scope"))
	assert.NotEmpty(t, query.Get("state"))
}

func TestAuthorizationScopes(t *testing.T) {
	assert.Equal(t,
		[]string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		oidc.AuthorizationScopes(oidc.OIDCConfiguration{}),
	)
	assert.Equal(t,
		[]string{oidc.ScopeOpenID, oidc.ScopeEmail},
		oidc.AuthorizationScopes(oidc.OIDCConfiguration{BaseConfiguration: oidc.BaseConfiguration{ScopesSupported: []string{oidc.ScopeOpenID, oidc.ScopeEmail}}}),
	)
	assert.Equal(t,
		[]string{"custom.scope"},
		oidc.AuthorizationScopes(oidc.OIDCConfiguration{}, "custom.scope"),
	)
	assert.Equal(t,
		[]string{"projects:read", "projects:write"},
		oidc.OAuthAuthorizationScopes(oidc.OAuthConfiguration{BaseConfiguration: oidc.BaseConfiguration{ScopesSupported: []string{"projects:read", "projects:write"}}}),
	)
	assert.Equal(t,
		[]string{"custom.scope"},
		oidc.OAuthAuthorizationScopes(oidc.OAuthConfiguration{}, "custom.scope"),
	)
	assert.Nil(t, oidc.OAuthAuthorizationScopes(oidc.OAuthConfiguration{}))
}

func TestAuthorizationCodeFlowValidateCallback(t *testing.T) {
	flow := &oidc.AuthorizationCodeFlow{State: "expected-state"}
	code, err := flow.ValidateCallback("test-code", "expected-state")
	require.NoError(t, err)
	assert.Equal(t, "test-code", code)
}

func TestAuthorizationCodeFlowValidateCallbackStateMismatch(t *testing.T) {
	flow := &oidc.AuthorizationCodeFlow{State: "expected-state"}
	_, err := flow.ValidateCallback("test-code", "other-state")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "state mismatch")
}

func TestAuthorizationCodeFlowValidateCallbackMissingCode(t *testing.T) {
	flow := &oidc.AuthorizationCodeFlow{State: "expected-state"}
	_, err := flow.ValidateCallback("", "expected-state")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "missing code")
}
