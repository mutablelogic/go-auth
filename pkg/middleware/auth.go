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
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// NewAuth returns an HTTP middleware that verifies a locally issued JWT,
// extracts the embedded session and user claims, and rejects revoked or expired
// sessions or users.
func NewAuthN(mgr *manager.Manager) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				writeUnauthorized(w, r, mgr, "invalid_request", "missing bearer token")
				return
			}
			issuer, err := mgr.OIDCIssuer()
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
				return
			}
			claims, err := mgr.OIDCVerify(token, issuer)
			if err != nil {
				writeUnauthorized(w, r, mgr, "invalid_token", err)
				return
			}
			session, err := sessionFromClaims(claims)
			if err != nil {
				writeUnauthorized(w, r, mgr, "invalid_token", err)
				return
			}
			user, err := userFromClaims(claims)
			if err != nil {
				writeUnauthorized(w, r, mgr, "invalid_token", err)
				return
			}
			if err := validateClaimBindings(claims, user, session); err != nil {
				writeUnauthorized(w, r, mgr, "invalid_token", err)
				return
			}
			if session.RevokedAt != nil {
				writeUnauthorized(w, r, mgr, "invalid_token", "session is revoked")
				return
			}
			now := time.Now().UTC()
			if !session.ExpiresAt.After(now) {
				writeUnauthorized(w, r, mgr, "invalid_token", "session is expired")
				return
			}
			if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
				writeUnauthorized(w, r, mgr, "invalid_token", "user is expired")
				return
			}
			if user.Status != nil && *user.Status != schema.UserStatusActive {
				writeUnauthorized(w, r, mgr, "invalid_token", "user is not active")
				return
			}
			next(w, r.WithContext(withAuthContext(r.Context(), claims, user, session)))
		}
	}
}

// NewMiddleware preserves the older constructor name used by tests and
// callers while delegating to NewAuthN.
func NewMiddleware(mgr *manager.Manager) func(http.HandlerFunc) http.HandlerFunc {
	return NewAuthN(mgr)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func sessionFromClaims(claims map[string]any) (*schema.Session, error) {
	session, err := decodeClaim[schema.Session](claims, "session")
	if err != nil {
		return nil, err
	}
	return &session, nil
}

func userFromClaims(claims map[string]any) (*schema.User, error) {
	user, err := decodeClaim[schema.User](claims, "user")
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func validateClaimBindings(claims map[string]any, user *schema.User, session *schema.Session) error {
	if user == nil || session == nil {
		return httpresponse.Err(http.StatusBadRequest).With("token missing user or session claim")
	}
	if session.User != user.ID {
		return httpresponse.Err(http.StatusBadRequest).With("token session does not match token user")
	}
	if value, ok := claims["sub"].(string); !ok || strings.TrimSpace(value) == "" {
		return httpresponse.Err(http.StatusBadRequest).With("token missing sub claim")
	} else if value != uuid.UUID(user.ID).String() {
		return httpresponse.Err(http.StatusBadRequest).With("token sub does not match token user")
	}
	if value, ok := claims["sid"].(string); !ok || strings.TrimSpace(value) == "" {
		return httpresponse.Err(http.StatusBadRequest).With("token missing sid claim")
	} else if value != uuid.UUID(session.ID).String() {
		return httpresponse.Err(http.StatusBadRequest).With("token sid does not match token session")
	}
	return nil
}

func decodeClaim[T any](claims map[string]any, key string) (T, error) {
	var result T
	value, ok := claims[key]
	if !ok || value == nil {
		return result, httpresponse.Err(http.StatusBadRequest).Withf("token missing %s claim", key)
	}
	data, err := json.Marshal(value)
	if err != nil {
		return result, httpresponse.Err(http.StatusBadRequest).Withf("encode %s claim: %v", key, err)
	}
	if err := json.Unmarshal(data, &result); err != nil {
		return result, httpresponse.Err(http.StatusBadRequest).Withf("decode %s claim: %v", key, err)
	}
	return result, nil
}

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

func writeUnauthorized(w http.ResponseWriter, r *http.Request, mgr *manager.Manager, code string, detail any) {
	description := strings.TrimSpace(fmt.Sprint(detail))
	challenge := []string{fmt.Sprintf(`error=%q`, strings.TrimSpace(code))}
	if description != "" {
		challenge = append(challenge, fmt.Sprintf(`error_description=%q`, description))
	}
	if mgr != nil {
		if issuer, err := mgr.OIDCIssuer(); err == nil {
			resourceMetadata := strings.TrimRight(issuer, "/") + "/" + oidc.ProtectedResourcePath
			challenge = append(challenge, fmt.Sprintf(`resource_metadata=%q`, resourceMetadata))
		}
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(challenge, ", "))
	_ = httpresponse.Error(w, httpresponse.ErrNotAuthorized.With(detail))
}
