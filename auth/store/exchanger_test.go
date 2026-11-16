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

package store_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	// Packages
	file "github.com/mutablelogic/go-auth/auth/provider/file"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	store "github.com/mutablelogic/go-auth/auth/store"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// users is a user store, whose only user is alice, by her email address,
// with a scope
type users struct{}

func (users) User(_ context.Context, identity *schema.Identity) (*schema.User, error) {
	if identity.Email != "alice@example.com" {
		return nil, httpresponse.ErrNotFound.With(identity.Email)
	}
	return &schema.User{ID: "alice", Name: "Alice", Email: identity.Email, Groups: []string{"staff"}}, nil
}

func (users) Scopes(_ context.Context, user *schema.User) ([]string, error) {
	return []string{"cert:read"}, nil
}

var alice = &schema.Identity{Provider: "google", Issuer: "https://accounts.google.com", Subject: "g1", Email: "alice@example.com", Name: "Alice", Groups: []string{"g"}}

func newSessions(t *testing.T) *file.Sessions {
	t.Helper()
	sessions, err := file.New(filepath.Join(t.TempDir(), "sessions"))
	require.NoError(t, err)
	return sessions
}

func Test_Exchange(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

	t.Run("WithoutUsers", func(t *testing.T) {
		// The user is the identity, without scopes
		sessions := newSessions(t)
		e, err := store.NewExchanger(sessions, store.WithClock(func() time.Time { return now }), store.WithTTL(time.Hour))
		require.NoError(t, err)
		result, err := e.Exchange(ctx, alice)
		require.NoError(t, err)
		token := result.(*schema.SessionToken)
		assert.Equal(t, schema.User{ID: "https%3A%2F%2Faccounts.google.com#g1", Name: "Alice", Email: "alice@example.com", Groups: []string{"g"}}, token.User)
		assert.Empty(t, token.Scopes)
		assert.Equal(t, "google", token.Provider)
		assert.Equal(t, now.Add(time.Hour), token.ExpiresAt)
	})

	t.Run("WithUsers", func(t *testing.T) {
		sessions := newSessions(t)
		e, err := store.NewExchanger(sessions, store.WithUsers(users{}))
		require.NoError(t, err)
		result, err := e.Exchange(ctx, alice)
		require.NoError(t, err)
		token := result.(*schema.SessionToken)
		assert.Equal(t, "alice", token.User.ID)
		assert.Equal(t, []string{"cert:read"}, token.Scopes)

		// The session is the store's, by its token
		session, err := sessions.Session(ctx, token.Token)
		require.NoError(t, err)
		assert.Equal(t, []string{"cert:read"}, session.Scopes)

		// An identity which isn't a user is forbidden
		_, err = e.Exchange(ctx, &schema.Identity{Provider: "google", Subject: "g2", Email: "bob@example.com"})
		assert.ErrorIs(t, err, httpresponse.ErrForbidden)
	})

	t.Run("Hook", func(t *testing.T) {
		// The hook refuses identities, before they're exchanged
		hook := func(_ context.Context, identity *schema.Identity) error {
			if !strings.HasSuffix(identity.Email, "@example.com") {
				return httpresponse.ErrForbidden.With("Only example.com")
			}
			return nil
		}
		e, err := store.NewExchanger(newSessions(t), store.WithHook(hook))
		require.NoError(t, err)
		_, err = e.Exchange(ctx, alice)
		assert.NoError(t, err)
		_, err = e.Exchange(ctx, &schema.Identity{Provider: "github", Subject: "1", Email: "mallory@evil.test"})
		assert.ErrorIs(t, err, httpresponse.ErrForbidden)
	})

	t.Run("Needs", func(t *testing.T) {
		_, err := store.NewExchanger(nil)
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
		_, err = store.NewExchanger(newSessions(t), store.WithTTL(0))
		assert.ErrorIs(t, err, httpresponse.ErrBadRequest)
	})
}

func Test_AllowDomains(t *testing.T) {
	ctx := context.Background()
	hook := store.AllowDomains("example.com", "@Example.ORG")
	assert.NoError(t, hook(ctx, &schema.Identity{Email: "alice@EXAMPLE.com", EmailVerified: true}))
	assert.NoError(t, hook(ctx, &schema.Identity{Email: "bob@example.org", EmailVerified: true}))
	assert.ErrorIs(t, hook(ctx, &schema.Identity{Email: "alice@example.com"}), httpresponse.ErrForbidden, "not verified")
	assert.ErrorIs(t, hook(ctx, &schema.Identity{Email: "mallory@example.com.evil", EmailVerified: true}), httpresponse.ErrForbidden)
	assert.ErrorIs(t, hook(ctx, &schema.Identity{Name: "no email"}), httpresponse.ErrForbidden)
}

func Test_IdentityID(t *testing.T) {
	// By the issuer and subject, not the provider's name, and unambiguous
	a := store.IdentityID(&schema.Identity{Provider: "oidc", Issuer: "https://one.example", Subject: "1"})
	assert.Equal(t, a, store.IdentityID(&schema.Identity{Provider: "renamed", Issuer: "https://one.example", Subject: "1"}))
	assert.NotEqual(t, a, store.IdentityID(&schema.Identity{Provider: "oidc", Issuer: "https://two.example", Subject: "1"}))
	assert.NotEqual(t,
		store.IdentityID(&schema.Identity{Issuer: "a#b", Subject: "c"}),
		store.IdentityID(&schema.Identity{Issuer: "a", Subject: "b#c"}))
}
