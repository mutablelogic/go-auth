package oidc_test

import (
	"fmt"
	"net/url"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
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

func TestClientConfigurationPublic(t *testing.T) {
	assert := assert.New(t)

	config := oidc.ClientConfiguration{
		PublicClientConfiguration: oidc.PublicClientConfiguration{
			Issuer:   oidc.GoogleIssuer,
			ClientID: "google-client-id",
			Provider: "oauth",
		},
		ClientSecret: "google-client-secret",
	}

	public := config.Public()
	assert.Equal(oidc.GoogleIssuer, public.Issuer)
	assert.Equal("google-client-id", public.ClientID)
	assert.Equal("oauth", public.Provider)
}

func TestConfigURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/.well-known/openid-configuration",
		oidc.ConfigURL("https://issuer.example.com/api/"),
	)
}

func TestJWKSURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/.well-known/jwks.json",
		oidc.JWKSURL("https://issuer.example.com/api/"),
	)
}

func TestAuthCodeURL(t *testing.T) {
	assert.Equal(t,
		"https://issuer.example.com/api/auth/code",
		oidc.AuthCodeURL("https://issuer.example.com/api/"),
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
	flow, err := oidc.NewAuthorizationCodeFlow(oidc.Configuration{
		Issuer:                oidc.GoogleIssuer,
		AuthorizationEndpoint: "https://accounts.example.test/o/oauth2/v2/auth",
		TokenEndpoint:         "https://accounts.example.test/token",
		ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		CodeChallengeMethods:  []string{oidc.CodeChallengeMethodPlain, oidc.CodeChallengeMethodS256},
	}, "client-id", "http://127.0.0.1:8085/callback")
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

func TestAuthorizationScopes(t *testing.T) {
	assert.Equal(t,
		[]string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		oidc.AuthorizationScopes(oidc.Configuration{}),
	)
	assert.Equal(t,
		[]string{oidc.ScopeOpenID, oidc.ScopeEmail},
		oidc.AuthorizationScopes(oidc.Configuration{ScopesSupported: []string{oidc.ScopeOpenID, oidc.ScopeEmail}}),
	)
	assert.Equal(t,
		[]string{"custom.scope"},
		oidc.AuthorizationScopes(oidc.Configuration{}, "custom.scope"),
	)
}
