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

package manager

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	// Packages
	uuid "github.com/google/uuid"
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// AuthenticateBearer verifies a locally issued access token and returns the
// public authenticated user shape together with the session required by HTTP middleware.
func (m *Manager) AuthenticateBearer(ctx context.Context, token string) (_ *schema.UserInfo, _ *schema.Session, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "AuthenticateBearer",
		attribute.Int("token_length", len(strings.TrimSpace(token))),
	)
	defer func() { endSpan(err) }()

	issuer, err := m.Issuer()
	if err != nil {
		return nil, nil, auth.ErrInternalServerError.With(err)
	}

	claims, err := m.OIDCVerify(token, issuer)
	if err != nil {
		return nil, nil, err
	}
	if err := validateTokenUse(claims); err != nil {
		return nil, nil, err
	}

	session, err := sessionFromClaims(claims)
	if err != nil {
		return nil, nil, err
	}

	now := time.Now().UTC()
	if session.RevokedAt != nil {
		return nil, nil, httpresponse.Err(http.StatusBadRequest).With("session is revoked")
	}
	if !session.ExpiresAt.After(now) {
		return nil, nil, httpresponse.Err(http.StatusBadRequest).With("session is expired")
	}
	if userinfo, ok := m.cachedSessionUserInfo(session.ID); ok {
		if err := validateClaimBindings(claims, &userinfo, session); err != nil {
			return nil, nil, err
		}
		return &userinfo, session, nil
	}

	user, err := userFromClaims(claims)
	if err != nil {
		return nil, nil, err
	}
	userinfo := schema.NewUserInfo(user)
	if err := validateClaimBindings(claims, userinfo, session); err != nil {
		return nil, nil, err
	}
	if user.ExpiresAt != nil && !user.ExpiresAt.After(now) {
		return nil, nil, httpresponse.Err(http.StatusBadRequest).With("user is expired")
	}
	if user.Status != nil && *user.Status != schema.UserStatusActive {
		return nil, nil, httpresponse.Err(http.StatusBadRequest).With("user is not active")
	}
	m.cacheSessionUserInfo(session, userinfo)

	return userinfo, session, nil
}

// AuthenticateKey validates an API key token and returns the public
// authenticated user shape together with the key required by HTTP middleware.
func (m *Manager) AuthenticateKey(ctx context.Context, token string) (_ *schema.UserInfo, _ *schema.Key, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "AuthenticateKey",
		attribute.Int("token_length", len(strings.TrimSpace(token))),
	)
	defer func() { endSpan(err) }()

	key, user, err := m.GetKeyByToken(ctx, token)
	if err != nil {
		return nil, nil, err
	}
	if key == nil || user == nil {
		return nil, nil, httpresponse.Err(http.StatusUnauthorized).With("invalid API key")
	}
	if key.ExpiresAt != nil && !key.ExpiresAt.After(time.Now().UTC()) {
		return nil, nil, httpresponse.Err(http.StatusUnauthorized).With("API key is expired")
	}
	userinfo := schema.NewUserInfo(user)
	if userinfo == nil {
		return nil, nil, httpresponse.Err(http.StatusUnauthorized).With("invalid API key user")
	}
	return userinfo, key, nil
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

func validateClaimBindings(claims map[string]any, user *schema.UserInfo, session *schema.Session) error {
	if user == nil || session == nil {
		return httpresponse.Err(http.StatusBadRequest).With("token missing user or session claim")
	}
	if session.User != user.Sub {
		return httpresponse.Err(http.StatusBadRequest).With("token session does not match token user")
	}
	if value, ok := claims["sub"].(string); !ok || strings.TrimSpace(value) == "" {
		return httpresponse.Err(http.StatusBadRequest).With("token missing sub claim")
	} else if value != uuid.UUID(user.Sub).String() {
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

func (m *Manager) cachedSessionUserInfo(id schema.SessionID) (schema.UserInfo, bool) {
	if m == nil || m.sessioncache == nil {
		return schema.UserInfo{}, false
	}
	return m.sessioncache.Get(id)
}

func (m *Manager) cacheSessionUserInfo(session *schema.Session, userinfo *schema.UserInfo) {
	if m == nil || m.sessioncache == nil || session == nil || userinfo == nil {
		return
	}
	m.sessioncache.Set(session.ID, userinfo.Sub, *userinfo, session.ExpiresAt)
}

func (m *Manager) cachedKeyUserInfo(id schema.KeyID) (schema.UserInfo, bool) {
	if m == nil || m.keycache == nil {
		return schema.UserInfo{}, false
	}
	return m.keycache.Get(id)
}

func (m *Manager) cacheKeyUserInfo(key *schema.Key, userinfo *schema.UserInfo) {
	if m == nil || m.keycache == nil || key == nil || userinfo == nil {
		return
	}
	var expiry time.Time
	if key.ExpiresAt != nil {
		expiry = *key.ExpiresAt
	}
	m.keycache.Set(key.ID, userinfo.Sub, *userinfo, expiry)
}

func userFromUserInfo(userinfo schema.UserInfo) schema.User {
	return schema.User{
		ID:     userinfo.Sub,
		Scopes: append([]string(nil), userinfo.Scopes...),
		UserMeta: schema.UserMeta{
			Name:   userinfo.Name,
			Email:  userinfo.Email,
			Groups: append([]string(nil), userinfo.Groups...),
		},
	}
}
