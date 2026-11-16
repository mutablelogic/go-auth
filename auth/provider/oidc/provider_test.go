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
	"bytes"
	"context"
	"net/url"
	"testing"
	"time"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	oidc "github.com/mutablelogic/go-auth/auth/provider/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	test "github.com/mutablelogic/go-auth/auth/test"
	client "github.com/mutablelogic/go-client"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// signIn returns the credential of a sign-in with the provider, at the
// fake issuer, whose ID token has the claims, after checking the sign-in
// page's URL
func signIn(t *testing.T, ctx context.Context, i *test.OIDC, p *oidc.Provider, claims map[string]any) schema.Credential {
	t.Helper()
	authURL, err := p.AuthCodeURL(ctx, "http://127.0.0.1/callback", "state", provider.NewVerifier())
	require.NoError(t, err)
	u, err := url.Parse(authURL)
	require.NoError(t, err)
	assert.Equal(t, i.URL+"/authorize", u.Scheme+"://"+u.Host+u.Path)
	assert.Equal(t, "state", u.Query().Get("state"))
	assert.Equal(t, "openid email profile groups", u.Query().Get("scope"))
	return test.SignIn(t, ctx, p, func(challenge string) string { return i.Code(challenge, claims) })
}

func Test_Provider(t *testing.T) {
	ctx := context.Background()
	i := test.NewOIDC(t)
	credentials := test.NewCredentials().WithClient("keycloak", i.Audience, "secret")
	p, err := oidc.New("keycloak", "Keycloak", i.URL, credentials, "keycloak", oidc.WithScopes("groups"), oidc.WithGroupsClaim("groups"))
	require.NoError(t, err)
	assert.Equal(t, schema.ProviderMeta{Name: "keycloak", Label: "Keycloak", Kind: schema.ProviderKindRedirect}, p.Meta())

	t.Run("Identity", func(t *testing.T) {
		credential := signIn(t, ctx, i, p, map[string]any{
			"sub": "u1", "email": "alice@example.com", "email_verified": true, "name": "Alice", "groups": []string{"admins", "staff"}, "picture": "https://example.com/a.png",
		})
		identity, err := p.Exchange(ctx, credential)
		require.NoError(t, err)
		assert.Equal(t, &schema.Identity{
			Provider: "keycloak", Issuer: i.URL, Subject: "u1", Email: "alice@example.com", EmailVerified: true, Name: "Alice",
			Groups: []string{"admins", "staff"}, Claims: map[string]any{"picture": "https://example.com/a.png"},
		}, identity)

		// A code is only exchanged once
		_, err = p.Exchange(ctx, credential)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("WrongVerifier", func(t *testing.T) {
		credential := signIn(t, ctx, i, p, map[string]any{"sub": "u1"})
		credential.CodeVerifier = provider.NewVerifier()
		_, err := p.Exchange(ctx, credential)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("AnotherClient", func(t *testing.T) {
		// An ID token for another client isn't this client's
		credential := signIn(t, ctx, i, p, map[string]any{"sub": "u1", "aud": "another"})
		_, err := p.Exchange(ctx, credential)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("Expired", func(t *testing.T) {
		credential := signIn(t, ctx, i, p, map[string]any{"sub": "u1", "exp": time.Now().Add(-time.Hour).Unix()})
		_, err := p.Exchange(ctx, credential)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("NoCode", func(t *testing.T) {
		_, err := p.Exchange(ctx, schema.Credential{RedirectURL: "http://127.0.0.1/callback"})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	})
}

func Test_Discovery(t *testing.T) {
	ctx := context.Background()

	// An issuer which can't be reached is a gateway error, and is discovered
	// when it's next used
	i := test.NewOIDC(t)
	i.Close()
	credentials := test.NewCredentials().WithClient("down", i.Audience, "")
	p, err := oidc.New("down", "", i.URL, credentials, "down")
	require.NoError(t, err)
	assert.Equal(t, "down", p.Meta().Label, "the name, without a label")
	_, err = p.AuthCodeURL(ctx, "http://127.0.0.1/callback", "state", provider.NewVerifier())
	assert.ErrorIs(t, err, httpresponse.ErrGatewayError)

	// What's needed
	_, err = oidc.New("", "", i.URL, credentials, "down")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	_, err = oidc.New("x", "", "", credentials, "down")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	_, err = oidc.New("x", "", i.URL, nil, "down")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	_, err = oidc.New("x", "", i.URL, credentials, "")
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)

	// Google, by its issuer
	google, err := oidc.NewGoogle(credentials, "google")
	require.NoError(t, err)
	assert.Equal(t, schema.ProviderMeta{Name: "google", Label: "Google", Kind: schema.ProviderKindRedirect}, google.Meta())
}

func Test_ClientOptions(t *testing.T) {
	// The client's options are for discovery, the issuer's keys, and the
	// exchange, such as a trace of each request
	ctx := context.Background()
	i := test.NewOIDC(t)
	var trace bytes.Buffer
	p, err := oidc.New("traced", "", i.URL, test.NewCredentials().WithClient("traced", i.Audience, "secret"), "traced", oidc.WithClient(client.OptTrace(&trace, false)))
	require.NoError(t, err)
	credential := test.SignIn(t, ctx, p, func(challenge string) string { return i.Code(challenge, map[string]any{"sub": "u1"}) })
	_, err = p.Exchange(ctx, credential)
	require.NoError(t, err)
	for _, path := range []string{"/.well-known/openid-configuration", "/keys", "/token"} {
		assert.Contains(t, trace.String(), path)
	}
}

func Test_Credential(t *testing.T) {
	// The client is the credential, which is read when it's needed, so a
	// changed one is used, and one which isn't there, or isn't a client,
	// is an error
	ctx := context.Background()
	i := test.NewOIDC(t)
	credentials := test.NewCredentials()
	p, err := oidc.New("keycloak", "", i.URL, credentials, "keycloak")
	require.NoError(t, err)
	_, err = p.AuthCodeURL(ctx, "http://127.0.0.1/callback", "state", provider.NewVerifier())
	assert.ErrorIs(t, err, httpresponse.ErrInternalError, "not there")
	require.NoError(t, credentials.Set(ctx, "keycloak", []byte(`"a secret"`)))
	_, err = p.AuthCodeURL(ctx, "http://127.0.0.1/callback", "state", provider.NewVerifier())
	assert.ErrorIs(t, err, httpresponse.ErrInternalError, "not a client")

	for _, id := range []string{"first", "second"} {
		credentials.WithClient("keycloak", id, "secret")
		authURL, err := p.AuthCodeURL(ctx, "http://127.0.0.1/callback", "state", provider.NewVerifier())
		require.NoError(t, err)
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, id, u.Query().Get("client_id"))
	}
}

func Test_IssuerAsIs(t *testing.T) {
	// An issuer which ends with a slash is another issuer, which is kept as
	// it is, as discovery checks it's the same
	ctx := context.Background()
	i := test.NewOIDC(t)
	i.Issuer = i.URL + "/"
	p, err := oidc.New("slash", "", i.Issuer, test.NewCredentials().WithClient("slash", i.Audience, "secret"), "slash")
	require.NoError(t, err)
	identity, err := p.Exchange(ctx, test.SignIn(t, ctx, p, func(challenge string) string { return i.Code(challenge, map[string]any{"sub": "u1"}) }))
	require.NoError(t, err)
	assert.Equal(t, i.URL+"/", identity.Issuer)
}
