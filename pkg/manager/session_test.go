package manager_test

import (
	"context"
	"errors"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
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
}

func newSessionTestManager(t *testing.T, ttl time.Duration) *manager.Manager {
	t.Helper()
	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	m, err := manager.New(context.Background(), c, manager.WithSessionTTL(ttl))
	require.NoError(t, err)
	require.NoError(t, m.Exec(context.Background(), "TRUNCATE auth.user CASCADE"))

	return m
}

func mustLoginSession(t *testing.T, m *manager.Manager) (*schema.User, *schema.Session) {
	t.Helper()

	user, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
		IdentityKey: schema.IdentityKey{
			Provider: "https://accounts.google.com",
			Sub:      "refresh-subject",
		},
		IdentityMeta: schema.IdentityMeta{
			Email: "refresh.user@example.com",
			Claims: map[string]any{
				"name":  "Refresh User",
				"email": "refresh.user@example.com",
			},
		},
	})
	require.NoError(t, err)
	require.NotNil(t, user)
	require.NotNil(t, session)

	return user, session
}
