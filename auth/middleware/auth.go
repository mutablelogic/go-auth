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
	"errors"
	"fmt"
	"net/http"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Authenticator validates bearer tokens and API keys and returns the
// authenticated principal material used by downstream handlers.
type Authenticator interface {
	Issuer() (string, error)
	AuthenticateBearer(ctx context.Context, token string) (*schema.UserInfo, *schema.Session, error)
	AuthenticateKey(ctx context.Context, token string) (*schema.UserInfo, *schema.Key, error)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// AuthN returns an HTTP middleware that authenticates either a locally issued
// bearer token or an API key supplied via X-API-Key. If any check fails, a 401
// Unauthorized response is returned.
func AuthN(authenticator Authenticator) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			// Bearer token
			token, ok := bearerToken(r)
			if ok {
				user, session, err := authenticator.AuthenticateBearer(r.Context(), token)
				if err != nil {
					if errors.Is(err, auth.ErrInternalServerError) {
						_ = httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
					} else {
						writeUnauthorized(w, r, authenticator, "invalid_token", err.Error())
					}
					return
				}

				// Add auth context and call next handler
				next(w, r.WithContext(withAuthContext(r.Context(), user, session)))
				return
			}

			// API key
			if token, ok := apiKeyToken(r); ok {
				user, key, err := authenticator.AuthenticateKey(r.Context(), token)
				if err != nil {
					if errors.Is(err, auth.ErrInternalServerError) {
						_ = httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
					} else {
						_ = httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized).With(err))
					}
					return
				}

				next(w, r.WithContext(withAPIKeyContext(r.Context(), user, key)))
				return
			}

			// Neither
			writeUnauthorized(w, r, authenticator, "invalid_request", "missing bearer token or API key")
		}
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func bearerToken(r *http.Request) (string, bool) {
	value := strings.TrimSpace(r.Header.Get("Authorization"))
	if value == "" {
		return "", false
	}
	parts := strings.SplitN(value, " ", 2)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return "", false
	}
	token := strings.TrimSpace(parts[1])
	return token, token != ""
}

func writeUnauthorized(w http.ResponseWriter, r *http.Request, authenticator Authenticator, code string, detail any) {
	description := strings.TrimSpace(fmt.Sprint(detail))
	challenge := []string{fmt.Sprintf(`error=%q`, strings.TrimSpace(code))}
	if description != "" {
		challenge = append(challenge, fmt.Sprintf(`error_description=%q`, description))
	}
	if authenticator != nil {
		if issuer, err := authenticator.Issuer(); err == nil {
			resourceMetadata := strings.TrimRight(issuer, "/") + "/" + oidc.ProtectedResourcePath
			challenge = append(challenge, fmt.Sprintf(`resource_metadata=%q`, resourceMetadata))
		}
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(challenge, ", "))
	_ = httpresponse.Error(w, httpresponse.ErrNotAuthorized.With(detail))
}
