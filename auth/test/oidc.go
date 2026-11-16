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

// Package test has fake providers, which tests sign in with: an OpenID
// Connect issuer, and GitHub, each an HTTP server, which gives the identity
// it's told to, for a code, once, when it's exchanged with the verifier of
// its PKCE challenge.
package test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	// Packages
	jose "github.com/go-jose/go-jose/v4"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// OIDC is a fake OpenID Connect issuer, at its URL, which signs ID tokens,
// for its audience, the client ID, with a key it publishes
type OIDC struct {
	*httptest.Server
	Audience string

	t     testing.TB
	key   *rsa.PrivateKey
	codes *codes[map[string]any]
}

// codes are the codes a fake provider gives, by code: the S256 challenge
// they're exchanged with the verifier of, and what they're for
type codes[T any] struct {
	mu    sync.Mutex
	codes map[string]code[T]
}

type code[T any] struct {
	challenge string
	value     T
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewOIDC returns a fake issuer, whose audience is client, which is closed
// when the test ends
func NewOIDC(t testing.TB) *OIDC {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	i := &OIDC{Audience: "client", t: t, key: key, codes: newCodes[map[string]any]()}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{
			"issuer":                                i.URL,
			"authorization_endpoint":                i.URL + "/authorize",
			"token_endpoint":                        i.URL + "/token",
			"jwks_uri":                              i.URL + "/keys",
			"id_token_signing_alg_values_supported": []string{"RS256"},
		})
	})
	mux.HandleFunc("GET /keys", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, http.StatusOK, jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &i.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		claims, ok := i.codes.take(r.Form.Get("code"), r.Form.Get("code_verifier"))
		if !ok {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "The code, or its verifier, isn't right"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"access_token": "access", "token_type": "Bearer", "expires_in": 3600, "id_token": i.Sign(claims)})
	})
	i.Server = httptest.NewServer(mux)
	t.Cleanup(i.Close)
	return i
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Code returns a code for the challenge, whose ID token has the claims,
// which is exchanged once
func (i *OIDC) Code(challenge string, claims map[string]any) string {
	return i.codes.add(challenge, claims)
}

// Sign returns an ID token with the claims, from the issuer, for its
// audience, which expires in an hour, unless the claims say otherwise
func (i *OIDC) Sign(claims map[string]any) string {
	i.t.Helper()
	payload := map[string]any{"iss": i.URL, "aud": i.Audience, "iat": time.Now().Unix(), "exp": time.Now().Add(time.Hour).Unix()}
	for key, value := range claims {
		payload[key] = value
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: i.key}, (&jose.SignerOptions{}).WithType("JWT").WithHeader("kid", "k1"))
	require.NoError(i.t, err)
	data, err := json.Marshal(payload)
	require.NoError(i.t, err)
	signed, err := signer.Sign(data)
	require.NoError(i.t, err)
	token, err := signed.CompactSerialize()
	require.NoError(i.t, err)
	return token
}

// SignIn returns the credential of a sign-in with a provider: the code the
// fake gives for the challenge of the provider's sign-in page, with its
// verifier, and the redirect URL. code returns the code for a challenge,
// such as one of OIDC's, or GitHub's.
func SignIn(t testing.TB, ctx context.Context, p provider.RedirectProvider, code func(challenge string) string) schema.Credential {
	t.Helper()
	verifier := provider.NewVerifier()
	redirect := "http://127.0.0.1/callback"
	authURL, err := p.AuthCodeURL(ctx, redirect, "state", verifier)
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	require.Equal(t, "S256", u.Query().Get("code_challenge_method"))
	return schema.Credential{Code: code(u.Query().Get("code_challenge")), CodeVerifier: verifier, RedirectURL: redirect}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func newCodes[T any]() *codes[T] {
	return &codes[T]{codes: make(map[string]code[T])}
}

// add returns a new code for the challenge, and what it's for
func (c *codes[T]) add(challenge string, value T) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := provider.NewVerifier()
	c.codes[key] = code[T]{challenge: challenge, value: value}
	return key
}

// take returns what a code is for, once, when the verifier is its
// challenge's
func (c *codes[T]) take(key, verifier string) (T, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	found, ok := c.codes[key]
	delete(c.codes, key)
	sum := sha256.Sum256([]byte(verifier))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != found.challenge {
		var zero T
		return zero, false
	}
	return found.value, true
}

// writeJSON writes the value as JSON, with the status
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
