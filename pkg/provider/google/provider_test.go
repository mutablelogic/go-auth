package google

import (
	"context"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	providerpkg "github.com/djthorpe/go-auth/pkg/provider"
	jwt "github.com/golang-jwt/jwt/v5"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestNewValidation(t *testing.T) {
	_, err := New("", "secret")
	require.EqualError(t, err, "client_id is required")

	_, err = New("client-id", "")
	require.EqualError(t, err, "client_secret is required")

	_, err = NewWithIssuer("client-id", "secret", "")
	require.EqualError(t, err, "issuer is required")
}

func TestBeginAuthorizationAndExchange(t *testing.T) {
	testProvider := newTestOIDCProvider(t, "google-client-id", "google-client-secret", "nonce-123")
	defer testProvider.Close()

	provider, err := NewWithIssuer("google-client-id", "google-client-secret", testProvider.Issuer())
	require.NoError(t, err)

	resp, err := provider.BeginAuthorization(context.Background(), providerpkg.AuthorizationRequest{
		ClientID:            "ignored-local-client",
		RedirectURL:         "http://127.0.0.1:8085/callback",
		State:               "state-123",
		Scopes:              []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
		Nonce:               "nonce-123",
		CodeChallenge:       "challenge-123",
		CodeChallengeMethod: "S256",
		LoginHint:           "user@example.com",
	})
	require.NoError(t, err)
	uri, err := url.Parse(resp.RedirectURL)
	require.NoError(t, err)
	assert.Equal(t, "/authorize", uri.Path)
	assert.Equal(t, "google-client-id", uri.Query().Get("client_id"))
	assert.Equal(t, "http://127.0.0.1:8085/callback", uri.Query().Get("redirect_uri"))
	assert.Equal(t, "code", uri.Query().Get("response_type"))
	assert.Equal(t, "state-123", uri.Query().Get("state"))
	assert.Equal(t, "challenge-123", uri.Query().Get("code_challenge"))
	assert.Equal(t, "S256", uri.Query().Get("code_challenge_method"))
	assert.Equal(t, "nonce-123", uri.Query().Get("nonce"))
	assert.Equal(t, "user@example.com", uri.Query().Get("login_hint"))

	identity, err := provider.ExchangeAuthorizationCode(context.Background(), providerpkg.ExchangeRequest{
		Code:         "auth-code",
		RedirectURL:  "http://127.0.0.1:8085/callback",
		CodeVerifier: "verifier-123",
		Nonce:        "nonce-123",
	})
	require.NoError(t, err)
	assert.Equal(t, testProvider.Issuer(), identity.Provider)
	assert.Equal(t, "auth-code-success", identity.Sub)
	assert.Equal(t, "auth.code.success@example.com", identity.Email)
	assert.Equal(t, "auth-code", testProvider.FormValue("code"))
	assert.Equal(t, "http://127.0.0.1:8085/callback", testProvider.FormValue("redirect_uri"))
	assert.Equal(t, "verifier-123", testProvider.FormValue("code_verifier"))
}

func TestExchangeAuthorizationCodeRejectsNonceMismatch(t *testing.T) {
	testProvider := newTestOIDCProvider(t, "google-client-id", "google-client-secret", "wrong-nonce")
	defer testProvider.Close()

	provider, err := NewWithIssuer("google-client-id", "google-client-secret", testProvider.Issuer())
	require.NoError(t, err)

	_, err = provider.ExchangeAuthorizationCode(context.Background(), providerpkg.ExchangeRequest{
		Code:        "auth-code",
		RedirectURL: "http://127.0.0.1:8085/callback",
		Nonce:       "nonce-123",
	})
	require.EqualError(t, err, "token nonce mismatch")
}

type testOIDCProvider struct {
	key          *rsa.PrivateKey
	clientID     string
	clientSecret string
	nonce        string
	server       *httptest.Server
	lastForm     url.Values
}

func newTestOIDCProvider(t *testing.T, clientID, clientSecret, nonce string) *testOIDCProvider {
	t.Helper()

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	provider := &testOIDCProvider{key: key, clientID: clientID, clientSecret: clientSecret, nonce: nonce}
	mux := http.NewServeMux()
	mux.HandleFunc("/"+oidc.ConfigPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(oidc.OIDCConfiguration{
			BaseConfiguration: oidc.BaseConfiguration{
				Issuer:                provider.server.URL,
				AuthorizationEndpoint: provider.server.URL + "/authorize",
				TokenEndpoint:         provider.server.URL + "/token",
				ResponseTypes:         []string{oidc.ResponseTypeCode},
				GrantTypesSupported:   []string{"authorization_code"},
				ScopesSupported:       []string{oidc.ScopeOpenID, oidc.ScopeEmail, oidc.ScopeProfile},
			},
			JwksURI:           oidc.JWKSURL(provider.server.URL),
			SigningAlgorithms: []string{oidc.SigningAlgorithm},
			SubjectTypes:      []string{"public"},
			ClaimsSupported:   []string{"iss", "sub", "aud", "exp", "iat", "email", "name", "nonce"},
		}))
	})
	mux.HandleFunc("/"+oidc.JWKSPath, func(w http.ResponseWriter, r *http.Request) {
		set, err := oidc.PublicJWKSet(key)
		require.NoError(t, err)
		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(set))
	})
	mux.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		provider.lastForm = cloneValues(r.PostForm)

		basicUser, basicPass, ok := r.BasicAuth()
		if !ok {
			basicUser = r.PostForm.Get("client_id")
			basicPass = r.PostForm.Get("client_secret")
		}
		assert.Equal(t, provider.clientID, basicUser)
		assert.Equal(t, provider.clientSecret, basicPass)

		idToken, err := oidc.SignToken(key, jwt.MapClaims{
			"iss":   provider.server.URL,
			"sub":   "auth-code-success",
			"aud":   provider.clientID,
			"exp":   time.Now().Add(time.Hour).Unix(),
			"iat":   time.Now().Unix(),
			"email": "auth.code.success@example.com",
			"name":  "Auth Code Success",
			"nonce": provider.nonce,
		})
		require.NoError(t, err)

		w.Header().Set("Content-Type", "application/json")
		require.NoError(t, json.NewEncoder(w).Encode(map[string]any{
			"access_token": "upstream-access-token",
			"id_token":     idToken,
			"token_type":   "Bearer",
			"expires_in":   3600,
		}))
	})
	provider.server = httptest.NewServer(mux)
	return provider
}

func (p *testOIDCProvider) Close() {
	if p != nil && p.server != nil {
		p.server.Close()
	}
}

func (p *testOIDCProvider) Issuer() string {
	if p == nil || p.server == nil {
		return ""
	}
	return p.server.URL
}

func (p *testOIDCProvider) FormValue(key string) string {
	if p == nil || p.lastForm == nil {
		return ""
	}
	return p.lastForm.Get(key)
}

func cloneValues(values url.Values) url.Values {
	if values == nil {
		return nil
	}
	clone := make(url.Values, len(values))
	for key, value := range values {
		clone[key] = append([]string(nil), value...)
	}
	return clone
}

func ExampleProvider_PublicConfig() {
	provider, _ := New("client-id", "client-secret")
	fmt.Println(provider.PublicConfig().Issuer)
	fmt.Println(provider.PublicConfig().ClientID)
	// Output:
	// https://accounts.google.com
	// client-id
}
