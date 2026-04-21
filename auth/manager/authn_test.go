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
	"crypto/rsa"
	"testing"
	"time"

	// Packages
	jwt "github.com/golang-jwt/jwt/v5"
	uuid "github.com/google/uuid"
	cache "github.com/mutablelogic/go-auth/auth/cache"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestAuthenticateBearerCachesUserInfo(t *testing.T) {
	assert := assert.New(t)
	require := require.New(t)

	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(err)

	issuer := "https://issuer.example.test/api"
	mgr := &Manager{}
	mgr.opt.issuer = issuer
	mgr.opt.signer = "test-main"
	mgr.opt.keys = map[string]*rsa.PrivateKey{"test-main": key}
	mgr.sessioncache = cache.New[schema.SessionID, schema.UserID, schema.UserInfo](DefaultCacheSize)

	status := schema.UserStatusActive
	user := &schema.User{
		ID:     schema.UserID(uuid.New()),
		Scopes: []string{"scope.read"},
		UserMeta: schema.UserMeta{
			Name:   "Test User",
			Email:  "test@example.com",
			Groups: []string{"admins"},
			Status: &status,
		},
	}
	session := &schema.Session{
		ID:        schema.SessionID(uuid.New()),
		User:      user.ID,
		ExpiresAt: time.Now().UTC().Add(15 * time.Minute),
		CreatedAt: time.Now().UTC(),
	}

	claims := jwt.MapClaims{
		"iss":     issuer,
		"sub":     uuid.UUID(user.ID).String(),
		"sid":     uuid.UUID(session.ID).String(),
		"iat":     time.Now().UTC().Unix(),
		"nbf":     time.Now().UTC().Unix(),
		"exp":     session.ExpiresAt.UTC().Unix(),
		"user":    user,
		"session": session,
	}
	token, err := mgr.OIDCSign(claims)
	require.NoError(err)

	gotUser, gotSession, err := mgr.AuthenticateBearer(context.Background(), token)
	require.NoError(err)
	assert.Equal(user.ID, gotUser.Sub)
	assert.Equal(session.ID, gotSession.ID)

	stats := mgr.sessioncache.Stats()
	assert.Equal(1, stats.Size)
	assert.Equal(int64(1), stats.Misses)
	assert.Equal(int64(0), stats.Hits)

	cached, ok := mgr.sessioncache.Get(session.ID)
	require.True(ok)
	assert.Equal(*schema.NewUserInfo(user), cached)

	gotUser, gotSession, err = mgr.AuthenticateBearer(context.Background(), token)
	require.NoError(err)
	assert.Equal(user.ID, gotUser.Sub)
	assert.Equal(session.ID, gotSession.ID)

	stats = mgr.sessioncache.Stats()
	assert.Equal(int64(2), stats.Hits)
	assert.Equal(int64(1), stats.Misses)

	assert.Equal(user.Email, gotUser.Email)
	assert.Equal(user.Name, gotUser.Name)
	assert.Equal(user.Groups, gotUser.Groups)
	assert.Equal(user.Scopes, gotUser.Scopes)
}
