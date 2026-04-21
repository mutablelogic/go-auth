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

package middleware

import (
	"context"
	"fmt"
	"net/http"
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// KeyAuthenticator validates an API key token and returns the authenticated
// principal material used by downstream handlers.
type KeyAuthenticator interface {
	AuthenticateKey(ctx context.Context, token string) (*schema.UserInfo, *schema.Key, error)
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

type apiKeyAuth struct {
	authenticator KeyAuthenticator
}

var _ httprouter.SecurityScheme = (*apiKeyAuth)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewAPIKeyAuth(authenticator KeyAuthenticator) *apiKeyAuth {
	return &apiKeyAuth{authenticator: authenticator}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func APIKeyAuthN(authenticator KeyAuthenticator) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token, ok := apiKeyToken(r)
			if !ok {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized).With("missing API key"))
				return
			}
			user, key, err := authenticator.AuthenticateKey(r.Context(), token)
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized).With(err))
				return
			}
			next(w, r.WithContext(withAPIKeyContext(r.Context(), user, key)))
		}
	}
}

func (a *apiKeyAuth) Spec() openapi.SecurityScheme {
	return openapi.SecurityScheme{
		Type: "apiKey",
		In:   "header",
		Name: "X-API-Key",
	}
}

func (a *apiKeyAuth) Wrap(handler http.HandlerFunc, scopes []string) http.HandlerFunc {
	wrapper := APIKeyAuthN(a.authenticator)
	return wrapper(func(w http.ResponseWriter, r *http.Request) {
		if user := UserFromContext(r.Context()); user == nil {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized).With("invalid API key: no user in context"))
			return
		} else if !user.HasAllScopes(scopes...) {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusForbidden).With("insufficient permissions"), fmt.Sprintf("Required scopes: %q", scopes))
			return
		}
		handler(w, r)
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func apiKeyToken(r *http.Request) (string, bool) {
	value := strings.TrimSpace(r.Header.Get("X-API-Key"))
	return value, value != ""
}
