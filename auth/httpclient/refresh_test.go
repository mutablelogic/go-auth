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
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	oauth2 "golang.org/x/oauth2"
)

// tokenEndpoint is a token endpoint, which refreshes a token, or refuses
// it, with the response of fn, and counts the requests with HTTP Basic, and
// with the secret in the form
type tokenEndpoint struct {
	basic, post atomic.Int32
}

func newTokenEndpoint(t *testing.T, fn func(w http.ResponseWriter, r *http.Request, basic bool)) (*tokenEndpoint, string) {
	e := new(tokenEndpoint)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		_, _, basic := r.BasicAuth()
		if basic {
			e.basic.Add(1)
		} else if r.PostForm.Get("client_secret") != "" {
			e.post.Add(1)
		}
		w.Header().Set("Content-Type", "application/json")
		fn(w, r, basic)
	}))
	t.Cleanup(server.Close)
	return e, server.URL
}

func refreshed(w http.ResponseWriter) {
	_, _ = w.Write([]byte(`{"access_token":"new","token_type":"Bearer","expires_in":3600}`))
}

func expired(endpoint string, secret string, methods ...string) *httpclient.Grant {
	return &httpclient.Grant{
		Server: httpclient.ServerMetadata{TokenEndpoint: endpoint, TokenEndpointAuthMethodsSupported: methods},
		Client: httpclient.Registration{ClientID: "client", ClientSecret: secret},
		Token:  &oauth2.Token{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Minute)},
	}
}

func Test_Refresh(t *testing.T) {
	ctx := context.Background()
	c, err := httpclient.New("http://localhost/")
	require.NoError(t, err)

	t.Run("Basic", func(t *testing.T) {
		e, endpoint := newTokenEndpoint(t, func(w http.ResponseWriter, r *http.Request, basic bool) { refreshed(w) })
		token, err := c.TokenSource(ctx, expired(endpoint, "secret"), nil).Token()
		require.NoError(t, err)
		assert.Equal(t, "new", token.AccessToken)
		assert.Equal(t, "refresh", token.RefreshToken, "the refresh token is kept")
		assert.Equal(t, int32(1), e.basic.Load())
		assert.Equal(t, int32(0), e.post.Load())
	})

	t.Run("PostFallback", func(t *testing.T) {
		// A server which refuses Basic is asked again, with the secret in the
		// form, which is then kept
		e, endpoint := newTokenEndpoint(t, func(w http.ResponseWriter, r *http.Request, basic bool) {
			if basic {
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"error":"invalid_client"}`))
				return
			}
			refreshed(w)
		})
		grant := expired(endpoint, "secret")
		var source oauth2.TokenSource = c.TokenSource(ctx, grant, func(token *oauth2.Token) { token.Expiry = time.Now().Add(-time.Minute) })
		_, err := source.Token()
		require.NoError(t, err)
		_, err = source.Token()
		require.NoError(t, err)
		assert.Equal(t, int32(1), e.basic.Load())
		assert.Equal(t, int32(2), e.post.Load())
	})

	t.Run("PostOnly", func(t *testing.T) {
		// A server which only supports the form isn't asked with Basic
		e, endpoint := newTokenEndpoint(t, func(w http.ResponseWriter, r *http.Request, basic bool) { refreshed(w) })
		_, err := c.TokenSource(ctx, expired(endpoint, "secret", "client_secret_post"), nil).Token()
		require.NoError(t, err)
		assert.Equal(t, int32(0), e.basic.Load())
		assert.Equal(t, int32(1), e.post.Load())
	})

	t.Run("Public", func(t *testing.T) {
		// A client without a secret sends its ID
		_, endpoint := newTokenEndpoint(t, func(w http.ResponseWriter, r *http.Request, basic bool) {
			if basic || r.PostForm.Get("client_id") != "client" {
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
			refreshed(w)
		})
		_, err := c.TokenSource(ctx, expired(endpoint, ""), nil).Token()
		require.NoError(t, err)
	})

	t.Run("Refused", func(t *testing.T) {
		// A refused refresh is ErrBadParameter, with the server's error
		_, endpoint := newTokenEndpoint(t, func(w http.ResponseWriter, r *http.Request, basic bool) {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte(`{"error":"invalid_grant","error_description":"revoked"}`))
		})
		_, err := c.TokenSource(ctx, expired(endpoint, ""), nil).Token()
		assert.ErrorIs(t, err, goauth.ErrBadParameter)
		var retrieve *oauth2.RetrieveError
		require.True(t, errors.As(err, &retrieve))
		assert.Equal(t, "invalid_grant", retrieve.ErrorCode)
		assert.Equal(t, http.StatusBadRequest, retrieve.Response.StatusCode)
		assert.Contains(t, err.Error(), "revoked")
	})

	t.Run("Failed", func(t *testing.T) {
		// A failed refresh is ErrServiceUnavailable, and isn't asked again
		e, endpoint := newTokenEndpoint(t, func(w http.ResponseWriter, r *http.Request, basic bool) {
			w.WriteHeader(http.StatusServiceUnavailable)
		})
		_, err := c.TokenSource(ctx, expired(endpoint, "secret"), nil).Token()
		assert.ErrorIs(t, err, goauth.ErrServiceUnavailable)
		var retrieve *oauth2.RetrieveError
		require.True(t, errors.As(err, &retrieve))
		assert.Equal(t, http.StatusServiceUnavailable, retrieve.Response.StatusCode)
		assert.Equal(t, int32(1), e.basic.Load())
		assert.Equal(t, int32(0), e.post.Load())
	})
}
