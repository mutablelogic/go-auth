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


package httpclient_test

import (
	"context"
	"net/http"
	"net/url"
	"testing"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	test "github.com/mutablelogic/go-auth/auth/test"
	client "github.com/mutablelogic/go-client"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

// browser approves an authorization at its URL, as a person would, and
// follows the redirect, to the callback
func browser(t *testing.T, o *test.OAuth) func(string) error {
	return func(authorizeURL string) error {
		to, err := o.Approve(authorizeURL)
		if err != nil {
			return err
		}
		resp, err := http.Get(to)
		if err != nil {
			return err
		}
		resp.Body.Close()
		return nil
	}
}

func Test_Login(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	o := test.NewOAuth(t)
	c, err := httpclient.New(o.ResourceURL())
	require.NoError(t, err)

	// The resource isn't authorized, and says how it is
	err = c.DoAuthWithContext(ctx, client.NewRequest(), nil)
	require.NotNil(t, httpclient.AsAuthError(err))

	// Signing in discovers its authorization server, registers a client,
	// with a loopback callback, and exchanges the code
	grant, err := c.Login(ctx, err, "go-auth test", nil, browser(t, o))
	require.NoError(t, err)
	assert.Equal(t, o.URL, grant.Server.Issuer)
	assert.Equal(t, o.ResourceURL(), grant.Resource)
	assert.Equal(t, []string{"read"}, grant.Scopes, "the challenge's")
	assert.NotEmpty(t, grant.Client.ClientID)
	require.NotNil(t, grant.Token)

	// With its token, the resource is authorized
	authorized, err := httpclient.New(o.ResourceURL(), client.OptReqToken(client.Token{Scheme: client.Bearer, Value: grant.Token.AccessToken}))
	require.NoError(t, err)
	var result map[string]bool
	require.NoError(t, authorized.DoAuthWithContext(ctx, client.NewRequest(), &result))
	assert.True(t, result["ok"])
}

func Test_Authorize(t *testing.T) {
	ctx := context.Background()
	o := test.NewOAuth(t)
	c, err := httpclient.New(o.ResourceURL())
	require.NoError(t, err)
	metadata, err := c.Discover(ctx, "")
	require.NoError(t, err)

	// A client which is registered beforehand, with a secret
	redirect := "http://127.0.0.1:1/callback"
	o.Client("fixed", "secret", redirect)
	registration := httpclient.Registration{ClientID: "fixed", ClientSecret: "secret"}

	exchange := func(t *testing.T, a *httpclient.Authorization, edit func(url.Values)) (*httpclient.Grant, error) {
		t.Helper()
		to, err := o.Approve(a.URL)
		require.NoError(t, err)
		u, err := url.Parse(to)
		require.NoError(t, err)
		query := u.Query()
		if edit != nil {
			edit(query)
		}
		return c.Exchange(ctx, a, query)
	}

	t.Run("Exchange", func(t *testing.T) {
		a, err := c.Authorize(metadata, registration, redirect, "read")
		require.NoError(t, err)
		u, err := url.Parse(a.URL)
		require.NoError(t, err)
		assert.Equal(t, "S256", u.Query().Get("code_challenge_method"))
		assert.Equal(t, o.ResourceURL(), u.Query().Get("resource"))
		grant, err := exchange(t, a, nil)
		require.NoError(t, err)
		assert.NotEmpty(t, grant.Token.AccessToken)
		assert.NotEmpty(t, grant.Token.RefreshToken)
	})

	t.Run("WrongState", func(t *testing.T) {
		a, err := c.Authorize(metadata, registration, redirect)
		require.NoError(t, err)
		_, err = exchange(t, a, func(q url.Values) { q.Set("state", "another") })
		assert.ErrorIs(t, err, goauth.ErrBadParameter)
	})

	t.Run("Refused", func(t *testing.T) {
		a, err := c.Authorize(metadata, registration, redirect)
		require.NoError(t, err)
		_, err = c.Exchange(ctx, a, url.Values{"state": {a.State}, "error": {"access_denied"}, "error_description": {"Not today"}})
		assert.ErrorIs(t, err, goauth.ErrBadParameter)
		assert.Contains(t, err.Error(), "Not today")
	})

	t.Run("Refresh", func(t *testing.T) {
		a, err := c.Authorize(metadata, registration, redirect)
		require.NoError(t, err)
		grant, err := exchange(t, a, nil)
		require.NoError(t, err)

		// An expired token is refreshed, and the new one is said
		grant.Token.Expiry = time.Now().Add(-time.Minute)
		var refreshed *oauth2.Token
		source := c.TokenSource(ctx, grant, func(token *oauth2.Token) { refreshed = token })
		token, err := source.Token()
		require.NoError(t, err)
		assert.NotEqual(t, grant.Token.AccessToken, token.AccessToken)
		assert.Equal(t, token, refreshed)

		// Not once they're revoked
		o.Revoke()
		token.Expiry = time.Now().Add(-time.Minute)
		_, err = c.TokenSource(ctx, &httpclient.Grant{Server: grant.Server, Client: grant.Client, RedirectURI: redirect, Token: token}, nil).Token()
		assert.Error(t, err)
	})

	t.Run("Needs", func(t *testing.T) {
		_, err := c.Authorize(metadata, registration, "not a url")
		assert.ErrorIs(t, err, goauth.ErrBadParameter)
		_, err = c.Authorize(metadata, httpclient.Registration{}, redirect)
		assert.ErrorIs(t, err, goauth.ErrBadParameter)
		_, err = c.Authorize(&httpclient.Metadata{AuthorizationServers: []httpclient.ServerMetadata{{Issuer: "x"}}}, registration, redirect)
		assert.ErrorIs(t, err, goauth.ErrNotImplemented, "without S256")
	})
}

func Test_Loopback(t *testing.T) {
	l, err := httpclient.NewLoopback()
	require.NoError(t, err)
	defer l.Close()
	u, err := url.Parse(l.RedirectURI())
	require.NoError(t, err)
	assert.Equal(t, "127.0.0.1", u.Hostname())

	// The first callback is waited for, and a second is refused
	resp, err := http.Get(l.RedirectURI() + "?code=c&state=s")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusOK, resp.StatusCode)
	resp, err = http.Get(l.RedirectURI() + "?code=again")
	require.NoError(t, err)
	resp.Body.Close()
	assert.Equal(t, http.StatusConflict, resp.StatusCode)
	query, err := l.Wait(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "c", query.Get("code"))

	// Until the context is done
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = l.Wait(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
}
