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
	uuid "github.com/google/uuid"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// TokenVerifier validates and decodes a bearer JWT token.
type TokenVerifier interface {
	Issuer() (string, error)
	OIDCVerify(token, issuer string) (map[string]any, error)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// AuthN returns an HTTP middleware that verifies a locally issued JWT,
// extracts the embedded session and user claims, and rejects revoked or expired
// sessions or users. If any check fails, a 401 Unauthorized
// response is returned with a WWW-Authenticate header containing the error details.
func AuthN(verifier TokenVerifier) func(http.HandlerFunc) http.HandlerFunc {
	return func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			token, ok := bearerToken(r)
			if !ok {
				writeUnauthorized(w, r, verifier, "invalid_request", "missing bearer token")
				return
			}
			issuer, err := verifier.Issuer()
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.ErrInternalError.With(err))
				return
			}
			claims, err := verifier.OIDCVerify(token, issuer)
			if err != nil {
				writeUnauthorized(w, r, verifier, "invalid_token", err.Error())
				return
			}
			if err := validateTokenUse(claims); err != nil {
				writeUnauthorized(w, r, verifier, "invalid_token", err.Error())
				return
			}
			session, err := sessionFromClaims(claims)
			if err != nil {
				writeUnauthorized(w, r, verifier, "invalid_token", err.Error())
				return
			}
			user, err := userFromClaims(claims)
			if err != nil {
				writeUnauthorized(w, r, verifier, "invalid_token", err.Error())
				return
			}
			if err := validateClaimBindings(claims, user, session); err != nil {
				writeUnauthorized(w, r, verifier, "invalid_token", err.Error())
				return
			}
			if session.RevokedAt != nil {
				writeUnauthorized(w, r, verifier, "invalid_token", "session is revoked")
				return
			}
			now := time.Now().UTC()
			if !session.ExpiresAt.After(now) {
				writeUnauthorized(w, r, verifier, "invalid_token", "session is expired")
				return
			}
			if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
				writeUnauthorized(w, r, verifier, "invalid_token", "user is expired")
				return
			}
			if user.Status != nil && *user.Status != schema.UserStatusActive {
				writeUnauthorized(w, r, verifier, "invalid_token", "user is not active")
				return
			}

			// Add auth context and call next handler
			next(w, r.WithContext(withAuthContext(r.Context(), claims, user, session)))
		}
	}
}

// NewMiddleware is kept as a compatibility wrapper for existing callers.
func NewMiddleware(verifier TokenVerifier) func(http.HandlerFunc) http.HandlerFunc {
	return AuthN(verifier)
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

func validateTokenUse(claims map[string]any) error {
	value, ok := claims["token_use"]
	if !ok || value == nil {
		return nil
	}
	use, ok := value.(string)
	if !ok || strings.TrimSpace(use) == "" {
		return httpresponse.Err(http.StatusBadRequest).With("token token_use claim is invalid")
	}
	if use != "access" {
		return httpresponse.Err(http.StatusBadRequest).Withf("token token_use must be %q", "access")
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

func writeUnauthorized(w http.ResponseWriter, r *http.Request, verifier TokenVerifier, code string, detail any) {
	description := strings.TrimSpace(fmt.Sprint(detail))
	challenge := []string{fmt.Sprintf(`error=%q`, strings.TrimSpace(code))}
	if description != "" {
		challenge = append(challenge, fmt.Sprintf(`error_description=%q`, description))
	}
	if verifier != nil {
		if issuer, err := verifier.Issuer(); err == nil {
			resourceMetadata := strings.TrimRight(issuer, "/") + "/" + oidc.ProtectedResourcePath
			challenge = append(challenge, fmt.Sprintf(`resource_metadata=%q`, resourceMetadata))
		}
	}
	w.Header().Set("WWW-Authenticate", "Bearer "+strings.Join(challenge, ", "))
	_ = httpresponse.Error(w, httpresponse.ErrNotAuthorized.With(detail))
}
