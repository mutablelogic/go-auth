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

package manager_test

import (
	"context"
	"errors"
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	authtest "github.com/mutablelogic/go-auth/auth/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	attribute "go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func Test_session_001(t *testing.T) {
	t.Run("RevokeSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		user, session := mustLoginSession(t, m)

		revoked, err := m.RevokeSession(context.Background(), session.ID)
		require.NoError(err)
		require.NotNil(revoked)
		require.NotNil(revoked.RevokedAt)
		assert.Equal(user.ID, revoked.User)
		assert.Equal(session.ID, revoked.ID)
		assert.False(revoked.RevokedAt.IsZero())

		refreshedUser, refreshedSession, err := m.RefreshSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(refreshedUser)
		assert.Nil(refreshedSession)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("RefreshSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		user, session := mustLoginSession(t, m)

		refreshedUser, refreshedSession, err := m.RefreshSession(context.Background(), session.ID)
		require.NoError(err)
		require.NotNil(refreshedUser)
		require.NotNil(refreshedSession)
		assert.Equal(user.ID, refreshedUser.ID)
		assert.Equal(user.ID, refreshedSession.User)
		assert.True(refreshedSession.ExpiresAt.After(session.ExpiresAt))
	})

	t.Run("RefreshSessionRejectsExpiredSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		_, session := mustLoginSession(t, m)

		require.NoError(m.With("id", session.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET expires_at = NOW() - INTERVAL '1 minute'
			WHERE id = @id
		`))

		user, refreshed, err := m.RefreshSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(user)
		assert.Nil(refreshed)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("RefreshSessionRejectsRevokedSession", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		_, session := mustLoginSession(t, m)

		require.NoError(m.With("id", session.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET revoked_at = NOW()
			WHERE id = @id
		`))

		user, refreshed, err := m.RefreshSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(user)
		assert.Nil(refreshed)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("RefreshSessionRejectsExpiredUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		user, session := mustLoginSession(t, m)

		require.NoError(m.With("id", user.ID).Exec(context.Background(), `
			UPDATE auth.user
			SET expires_at = NOW() - INTERVAL '1 minute'
			WHERE id = @id
		`))

		refreshedUser, refreshedSession, err := m.RefreshSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(refreshedUser)
		assert.Nil(refreshedSession)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("RefreshSessionRejectsInactiveUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		user, session := mustLoginSession(t, m)

		require.NoError(m.With("id", user.ID).With("status", schema.UserStatusInactive).Exec(context.Background(), `
			UPDATE auth.user
			SET status = @status
			WHERE id = @id
		`))

		refreshedUser, refreshedSession, err := m.RefreshSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(refreshedUser)
		assert.Nil(refreshedSession)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("RefreshSessionAllowsNilUserStatus", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManager(t, 30*time.Minute)
		user, session := mustLoginSession(t, m)

		require.NoError(m.With("id", user.ID).Exec(context.Background(), `
			UPDATE auth.user
			SET status = NULL
			WHERE id = @id
		`))

		refreshedUser, refreshedSession, err := m.RefreshSession(context.Background(), session.ID)
		require.NoError(err)
		require.NotNil(refreshedUser)
		require.NotNil(refreshedSession)
		assert.Equal(user.ID, refreshedUser.ID)
		assert.Equal(user.ID, refreshedSession.User)
		assert.True(refreshedSession.ExpiresAt.After(session.ExpiresAt))
	})

	t.Run("GetSessionTracing", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		exporter := tracetest.NewInMemoryExporter()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() {
			require.NoError(provider.Shutdown(context.Background()))
		}()

		m := newSessionTestManagerWithOpts(t, 30*time.Minute, manager.WithTracer(provider.Tracer("manager-session-test")))
		_, session := mustLoginSession(t, m)

		loaded, err := m.GetSession(context.Background(), session.ID)
		require.NoError(err)
		require.NotNil(loaded)

		require.NoError(provider.ForceFlush(context.Background()))
		spans := exporter.GetSpans()

		var getSessionSpan *tracetest.SpanStub
		for i := range spans {
			if spans[i].Name == "manager.GetSession" {
				getSessionSpan = &spans[i]
				break
			}
		}
		require.NotNil(getSessionSpan)
		assert.Contains(getSessionSpan.Attributes, attribute.String("session", session.ID.String()))
	})

	t.Run("RunPrunesRevokedSessions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManagerWithOpts(t, 30*time.Minute, manager.WithCleanup(10*time.Millisecond, 100))
		_, session := mustLoginSession(t, m)

		require.NoError(m.With("id", session.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET revoked_at = NOW()
			WHERE id = @id
		`))

		deletedSessions, err := m.CleanupSessions(context.Background())
		require.NoError(err)
		require.Len(deletedSessions, 1)
		assert.Equal(session.ID, deletedSessions[0].ID)
		assert.Equal(session.User, deletedSessions[0].User)
		require.NotNil(deletedSessions[0].RevokedAt)

		deleted, err := m.GetSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(deleted)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("CleanupSessionsLimitsOldestFirst", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManagerWithOpts(t, 30*time.Minute, manager.WithCleanup(time.Hour, 2))
		_, first := mustLoginSessionWithSub(t, m, "cleanup-1")
		_, second := mustLoginSessionWithSub(t, m, "cleanup-2")
		_, third := mustLoginSessionWithSub(t, m, "cleanup-3")

		require.NoError(m.With("id", first.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET revoked_at = NOW(), created_at = NOW() - INTERVAL '3 hour'
			WHERE id = @id
		`))
		require.NoError(m.With("id", second.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET revoked_at = NOW(), created_at = NOW() - INTERVAL '2 hour'
			WHERE id = @id
		`))
		require.NoError(m.With("id", third.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET revoked_at = NOW(), created_at = NOW() - INTERVAL '1 hour'
			WHERE id = @id
		`))

		deletedSessions, err := m.CleanupSessions(context.Background())
		require.NoError(err)
		require.Len(deletedSessions, 2)
		assert.Equal(first.ID, deletedSessions[0].ID)
		assert.Equal(second.ID, deletedSessions[1].ID)

		deleted, err := m.GetSession(context.Background(), first.ID)
		require.Error(err)
		assert.Nil(deleted)
		assert.True(errors.Is(err, auth.ErrNotFound))

		deleted, err = m.GetSession(context.Background(), second.ID)
		require.Error(err)
		assert.Nil(deleted)
		assert.True(errors.Is(err, auth.ErrNotFound))

		remaining, err := m.GetSession(context.Background(), third.ID)
		require.NoError(err)
		require.NotNil(remaining)
		assert.Equal(third.ID, remaining.ID)
	})

	t.Run("RunUsesCleanupSessions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newSessionTestManagerWithOpts(t, 30*time.Minute, manager.WithCleanup(10*time.Millisecond, 100))
		_, session := mustLoginSession(t, m)

		require.NoError(m.With("id", session.ID).Exec(context.Background(), `
			UPDATE auth.session
			SET revoked_at = NOW()
			WHERE id = @id
		`))

		ctx, cancel := context.WithTimeout(context.Background(), 25*time.Millisecond)
		defer cancel()
		err := m.Run(ctx)
		require.NoError(err)

		deleted, err := m.GetSession(context.Background(), session.ID)
		require.Error(err)
		assert.Nil(deleted)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})
}

func newSessionTestManager(t *testing.T, ttl time.Duration) *manager.Manager {
	t.Helper()
	return newSessionTestManagerWithOpts(t, ttl)
}

func newSessionTestManagerWithOpts(t *testing.T, ttl time.Duration, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	baseOpts := append([]manager.Opt{manager.WithSessionTTL(ttl)}, opts...)
	return authtest.NewManager(t, &conn,
		authtest.WithSchema("auth"),
		authtest.WithoutLocalProvider(),
		authtest.WithManagerOptions(baseOpts...),
	).Manager
}

func mustLoginSession(t *testing.T, m *manager.Manager) (*schema.User, *schema.Session) {
	t.Helper()
	return mustLoginSessionWithSub(t, m, "refresh-subject")
}

func mustLoginSessionWithSub(t *testing.T, m *manager.Manager, sub string) (*schema.User, *schema.Session) {
	t.Helper()

	user, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
		IdentityKey: schema.IdentityKey{
			Provider: "https://accounts.google.com",
			Sub:      sub,
		},
		IdentityMeta: schema.IdentityMeta{
			Email: sub + "@example.com",
			Claims: map[string]any{
				"name":  "Refresh User",
				"email": sub + "@example.com",
			},
		},
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, user)
	require.NotNil(t, session)

	return user, session
}
