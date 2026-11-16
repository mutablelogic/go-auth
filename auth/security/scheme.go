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

// Package security is the security scheme which the server's operations
// need, with their scopes: a session's token, as a bearer token, or the
// session's cookie, which a sign-in sets.
package security

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	store "github.com/mutablelogic/go-auth/auth/store"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Scheme authenticates a request with a session, by its token, and needs
// the scopes an operation has
type Scheme struct {
	sessions store.SessionStore
}

type sessionKey struct{}

var _ httprouter.SecurityScheme = (*Scheme)(nil)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// Name is the name the scheme is registered with, which operations
	// need it by
	Name = "bearerAuth"

	// CookieName is the name of the cookie with a session's token, which
	// a sign-in sets, for a browser
	CookieName = "goauth_session"
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns the scheme, with the sessions, which tokens are of
func New(sessions store.SessionStore) (*Scheme, error) {
	if sessions == nil {
		return nil, httpresponse.ErrBadRequest.With("The security scheme needs sessions")
	}
	return &Scheme{sessions: sessions}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Wrap calls the handler when the request's session, by its bearer token,
// or else its cookie, has the scopes, with the session in its context. It's
// 401 without a session, or one which isn't valid, and 403 without the
// scopes.
func (s *Scheme) Wrap(handler http.HandlerFunc, scopes []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := Token(r)
		if token == "" {
			unauthorized(w, "invalid_request", "A session's token, as a bearer token, or its cookie, is needed")
			return
		}
		session, err := s.sessions.Session(r.Context(), token)
		if errors.Is(err, httpresponse.ErrNotAuthorized) {
			unauthorized(w, "invalid_token", err.Error())
			return
		} else if err != nil {
			// The store failed, which isn't the token's fault, so it isn't
			// a challenge, nor says why, which is the server's
			_ = httpresponse.Error(w, httpresponse.ErrInternalError.With("The session couldn't be checked"))
			return
		}
		for _, scope := range scopes {
			if !slices.Contains(session.Scopes, scope) {
				w.Header().Set("WWW-Authenticate", `Bearer error="insufficient_scope", scope="`+strings.Join(scopes, " ")+`"`)
				_ = httpresponse.Error(w, httpresponse.ErrForbidden.Withf("The session needs the %q scope", scope))
				return
			}
		}
		// What a session is allowed isn't kept by a shared cache, for
		// another request, which wouldn't be checked
		w.Header().Set("Cache-Control", "no-store")
		handler(w, r.WithContext(context.WithValue(r.Context(), sessionKey{}, session)))
	}
}

// Spec is the scheme, in the OpenAPI specification: a bearer token, which a
// browser can send as a cookie instead
func (s *Scheme) Spec() openapi.SecurityScheme {
	return openapi.SecurityScheme{
		Type:        "http",
		Scheme:      "bearer",
		Description: "A session's token, which signing in returns, or its " + CookieName + " cookie, which signing in sets for a browser",
	}
}

// Session returns the session of a request the scheme has authenticated,
// from its context, or nil
func Session(ctx context.Context) *schema.Session {
	session, _ := ctx.Value(sessionKey{}).(*schema.Session)
	return session
}

// Token returns a request's session token: its bearer token, or else its
// session cookie, or empty
func Token(r *http.Request) string {
	if scheme, token, ok := strings.Cut(r.Header.Get("Authorization"), " "); ok && strings.EqualFold(scheme, "Bearer") {
		return strings.TrimSpace(token)
	}
	if cookie, err := r.Cookie(CookieName); err == nil {
		return cookie.Value
	}
	return ""
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// unauthorized writes 401, with the bearer scheme's challenge
func unauthorized(w http.ResponseWriter, code, reason string) {
	w.Header().Set("WWW-Authenticate", `Bearer error="`+code+`"`)
	_ = httpresponse.Error(w, httpresponse.ErrNotAuthorized.With(reason))
}
