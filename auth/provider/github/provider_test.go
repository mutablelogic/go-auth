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

package github_test

import (
	"bytes"
	"context"
	"net/url"
	"testing"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	client "github.com/mutablelogic/go-client"
	github "github.com/mutablelogic/go-auth/auth/provider/github"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	test "github.com/mutablelogic/go-auth/auth/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

var octocat = test.GitHubUser{
	ID: 583231, Login: "octocat", Name: "The Octocat",
	Emails: []test.GitHubEmail{{Email: "old@example.com", Verified: true}, {Email: "octocat@example.com", Primary: true, Verified: true}},
	Orgs:   []string{"github", "acme"},
}

func Test_Provider(t *testing.T) {
	ctx := context.Background()
	g := test.NewGitHub(t)
	p, err := github.New("client", "secret", github.WithURL(g.URL, g.APIURL()), github.WithOrganizations())
	require.NoError(t, err)
	assert.Equal(t, schema.ProviderMeta{Name: "github", Label: "GitHub", Kind: schema.ProviderKindRedirect}, p.Meta())

	t.Run("SignInPage", func(t *testing.T) {
		authURL, err := p.AuthCodeURL(ctx, "http://127.0.0.1/callback", "state", provider.NewVerifier())
		require.NoError(t, err)
		u, err := url.Parse(authURL)
		require.NoError(t, err)
		assert.Equal(t, g.URL+"/login/oauth/authorize", u.Scheme+"://"+u.Host+u.Path)
		assert.Equal(t, "read:user user:email read:org", u.Query().Get("scope"))
		assert.Equal(t, "client", u.Query().Get("client_id"))
	})

	t.Run("Identity", func(t *testing.T) {
		credential := test.SignIn(t, ctx, p, func(challenge string) string { return g.Code(challenge, octocat) })
		identity, err := p.Exchange(ctx, credential)
		require.NoError(t, err)
		assert.Equal(t, &schema.Identity{
			Provider: "github", Issuer: g.URL, Subject: "583231", Name: "The Octocat",
			Email: "octocat@example.com", EmailVerified: true, Groups: []string{"github", "acme"},
			Claims: map[string]any{"login": "octocat"},
		}, identity)

		// A code is only exchanged once, which GitHub refuses with 200
		_, err = p.Exchange(ctx, credential)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("WithoutName", func(t *testing.T) {
		// The login, without a name, and no organisations, unless they're
		// asked for
		plain, err := github.New("client", "secret", github.WithURL(g.URL, g.APIURL()))
		require.NoError(t, err)
		credential := test.SignIn(t, ctx, plain, func(challenge string) string {
			return g.Code(challenge, test.GitHubUser{ID: 1, Login: "anon", Orgs: []string{"acme"}})
		})
		identity, err := plain.Exchange(ctx, credential)
		require.NoError(t, err)
		assert.Equal(t, "anon", identity.Name)
		assert.Empty(t, identity.Email)
		assert.Empty(t, identity.Groups)
	})

	t.Run("WrongVerifier", func(t *testing.T) {
		credential := test.SignIn(t, ctx, p, func(challenge string) string { return g.Code(challenge, octocat) })
		credential.CodeVerifier = provider.NewVerifier()
		_, err := p.Exchange(ctx, credential)
		assert.ErrorIs(t, err, httpresponse.ErrNotAuthorized)
	})

	t.Run("Needs", func(t *testing.T) {
		_, err := github.New("", "secret")
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
		_, err = github.New("client", "")
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
		_, err = p.Exchange(ctx, schema.Credential{Code: "x"})
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	})
}

func Test_ClientOptions(t *testing.T) {
	// The client's options are for the exchange, and the API, such as a
	// trace of each request
	ctx := context.Background()
	g := test.NewGitHub(t)
	var trace bytes.Buffer
	p, err := github.New("client", "secret", github.WithURL(g.URL, g.APIURL()), github.WithClient(client.OptTrace(&trace, false)))
	require.NoError(t, err)
	credential := test.SignIn(t, ctx, p, func(challenge string) string { return g.Code(challenge, octocat) })
	_, err = p.Exchange(ctx, credential)
	require.NoError(t, err)
	for _, path := range []string{"/login/oauth/access_token", "/api/user", "/api/user/emails"} {
		assert.Contains(t, trace.String(), path)
	}
}
