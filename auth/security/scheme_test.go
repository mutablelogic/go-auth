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

package security_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	// Packages
	file "github.com/mutablelogic/go-auth/auth/provider/file"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	security "github.com/mutablelogic/go-auth/auth/security"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// newServer returns a server whose protected path needs the scope, and
// returns who's signed in, and a session's token, which has the scope
func newServer(t *testing.T) (*test.Server, string, string) {
	t.Helper()
	ctx := context.Background()
	sessions, err := file.New(filepath.Join(t.TempDir(), "sessions"))
	require.NoError(t, err)
	scheme, err := security.New(sessions)
	require.NoError(t, err)
	withScope, err := sessions.Create(ctx, schema.Session{User: schema.User{ID: "alice"}, Scopes: []string{"cert:read"}, ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)
	without, err := sessions.Create(ctx, schema.Session{User: schema.User{ID: "bob"}, ExpiresAt: time.Now().Add(time.Hour)})
	require.NoError(t, err)

	s := test.NewServer(t, func(router *httprouter.Router) error {
		if err := router.RegisterSecurityScheme(security.Name, scheme); err != nil {
			return err
		}
		return router.Register("protected", nil, func(path httprequest.PathItem) {
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				httpresponse.JSON(w, http.StatusOK, 0, security.Session(r.Context()).User.ID)
			}, func(op httprequest.PathOperation) {
				op.Response(http.StatusOK, "application/json", "Who's signed in")
				op.ErrorResponse(http.StatusUnauthorized)
				op.ErrorResponse(http.StatusForbidden)
				op.Security(security.Name, "cert:read")
			})
		})
	})
	return s, withScope.Token, without.Token
}

func Test_Scheme(t *testing.T) {
	s, token, without := newServer(t)

	// A bearer token, and a cookie, with the scope
	status, header, body := s.Request(t, http.MethodGet, "protected", http.Header{"Authorization": {"Bearer " + token}})
	assert.Equal(t, http.StatusOK, status)
	assert.Equal(t, "no-store", header.Get("Cache-Control"), "not kept by a shared cache")
	assert.Equal(t, `"alice"`, strings.TrimSpace(string(body)))
	status, _, _ = s.Request(t, http.MethodGet, "protected", http.Header{"Cookie": {security.CookieName + "=" + token}})
	assert.Equal(t, http.StatusOK, status)

	// Without a token, with one which isn't, and without the scope
	status, header, _ = s.Request(t, http.MethodGet, "protected", nil)
	assert.Equal(t, http.StatusUnauthorized, status)
	assert.Contains(t, header.Get("WWW-Authenticate"), "Bearer")
	status, _, _ = s.Request(t, http.MethodGet, "protected", http.Header{"Authorization": {"Bearer another"}})
	assert.Equal(t, http.StatusUnauthorized, status)
	status, header, _ = s.Request(t, http.MethodGet, "protected", http.Header{"Authorization": {"Bearer " + without}})
	assert.Equal(t, http.StatusForbidden, status)
	assert.Contains(t, header.Get("WWW-Authenticate"), `insufficient_scope`)

	// The scheme is in the specification
	assert.Equal(t, "bearer", s.Spec().Components.SecuritySchemes[security.Name].Scheme)
	assert.Empty(t, s.Verify())
}

func Test_Token(t *testing.T) {
	r, err := http.NewRequest(http.MethodGet, "/", nil)
	require.NoError(t, err)
	assert.Empty(t, security.Token(r))
	r.AddCookie(&http.Cookie{Name: security.CookieName, Value: "from-cookie"})
	assert.Equal(t, "from-cookie", security.Token(r))
	r.Header.Set("Authorization", "bearer from-header")
	assert.Equal(t, "from-header", security.Token(r), "a bearer token, first, in any case")
	r.Header.Set("Authorization", "Basic xyz")
	assert.Equal(t, "from-cookie", security.Token(r), "not another scheme")

	_, err = security.New(nil)
	assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
}

// broken is a session store which can't be read
type broken struct{}

func (broken) Create(context.Context, schema.Session) (*schema.SessionToken, error) {
	return nil, errors.New("the disk is on fire")
}

func (broken) Session(context.Context, string) (*schema.Session, error) {
	return nil, errors.New("the disk is on fire")
}

func (broken) Revoke(context.Context, string) error {
	return errors.New("the disk is on fire")
}

func Test_StoreFails(t *testing.T) {
	// A store which fails is the server's error, without a challenge, or
	// why
	scheme, err := security.New(broken{})
	require.NoError(t, err)
	called := false
	handler := scheme.Wrap(func(http.ResponseWriter, *http.Request) { called = true }, nil)
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.Header.Set("Authorization", "Bearer token")
	w := httptest.NewRecorder()
	handler(w, r)
	assert.False(t, called)
	assert.Equal(t, http.StatusInternalServerError, w.Code)
	assert.Empty(t, w.Header().Get("WWW-Authenticate"))
	assert.NotContains(t, w.Body.String(), "fire")
}

func Test_ResourceMetadata(t *testing.T) {
	sessions, err := file.New(filepath.Join(t.TempDir(), "sessions"))
	require.NoError(t, err)
	handler := func(w http.ResponseWriter, r *http.Request) {}

	// A path is on the request's host, and a URL is as it is
	scheme, err := security.New(sessions, security.WithResourceMetadata("/.well-known/oauth-protected-resource/api"))
	require.NoError(t, err)
	w := httptest.NewRecorder()
	scheme.Wrap(handler, nil)(w, httptest.NewRequest(http.MethodGet, "http://example.com/api/x", nil))
	assert.Equal(t, `Bearer resource_metadata="http://example.com/.well-known/oauth-protected-resource/api", error="invalid_request"`, w.Header().Get("WWW-Authenticate"))
	scheme, err = security.New(sessions, security.WithResourceMetadata("https://auth.example.com/.well-known/oauth-protected-resource"))
	require.NoError(t, err)
	w = httptest.NewRecorder()
	scheme.Wrap(handler, nil)(w, httptest.NewRequest(http.MethodGet, "http://example.com/api/x", http.NoBody))
	assert.Contains(t, w.Header().Get("WWW-Authenticate"), `resource_metadata="https://auth.example.com/.well-known/oauth-protected-resource"`)

	// Not one which isn't a path, or an http URL
	for _, metadata := range []string{"relative", "ftp://example.com/x", `/a"b`} {
		_, err = security.New(sessions, security.WithResourceMetadata(metadata))
		assert.Error(t, err, metadata)
	}
}
