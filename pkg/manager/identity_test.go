package manager_test

import (
	"context"
	"errors"
	"testing"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TESTS

func Test_identity_001(t *testing.T) {
	t.Run("ListIdentities", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		userA, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "User A",
			Email: "user.a@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(userA)

		userB, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "User B",
			Email: "user.b@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(userB)

		fixtures := []struct {
			user     uuid.UUID
			provider string
			sub      string
			email    string
		}{
			{user: uuid.UUID(userA.ID), provider: "github", sub: "alpha", email: "alpha@github.example.com"},
			{user: uuid.UUID(userA.ID), provider: "google", sub: "bravo", email: "bravo@google.example.com"},
			{user: uuid.UUID(userB.ID), provider: "microsoft", sub: "charlie", email: "charlie@microsoft.example.com"},
		}
		for _, fixture := range fixtures {
			identity, err := m.CreateIdentity(context.Background(), fixture.user, schema.IdentityInsert{
				IdentityKey:  schema.IdentityKey{Provider: fixture.provider, Sub: fixture.sub},
				IdentityMeta: schema.IdentityMeta{Email: fixture.email},
			})
			require.NoError(err)
			require.NotNil(identity)
		}

		limit := uint64(2)
		paged, err := m.ListIdentities(context.Background(), schema.IdentityListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit},
		})
		require.NoError(err)
		require.NotNil(paged)
		assert.Equal(uint(3), paged.Count)
		assert.Equal(uint64(1), paged.Offset)
		require.NotNil(paged.Limit)
		assert.Equal(uint64(2), *paged.Limit)
		require.Len(paged.Body, 2)
		assert.Equal("google", paged.Body[0].Provider)
		assert.Equal("microsoft", paged.Body[1].Provider)

		userAID := uuid.UUID(userA.ID)
		filtered, err := m.ListIdentities(context.Background(), schema.IdentityListRequest{
			User: &userAID,
		})
		require.NoError(err)
		require.NotNil(filtered)
		assert.Equal(uint(2), filtered.Count)
		require.Len(filtered.Body, 2)
		assert.Equal(userA.ID, filtered.Body[0].User)
		assert.Equal(userA.ID, filtered.Body[1].User)
		assert.Equal("github", filtered.Body[0].Provider)
		assert.Equal("google", filtered.Body[1].Provider)

		largeLimit := uint64(10)
		clamped, err := m.ListIdentities(context.Background(), schema.IdentityListRequest{
			OffsetLimit: pg.OffsetLimit{Limit: &largeLimit},
		})
		require.NoError(err)
		require.NotNil(clamped)
		assert.Equal(uint(3), clamped.Count)
		require.NotNil(clamped.Limit)
		assert.Equal(uint64(3), *clamped.Limit)
		require.Len(clamped.Body, 3)
	})

	t.Run("CreateGetUpdateDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Identity User",
			Email: "identity.user@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(user)

		beforeCreate := time.Now()
		created, err := m.CreateIdentity(context.Background(), uuid.UUID(user.ID), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "github",
				Sub:      "alice-123",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "alice@users.noreply.github.com",
				Claims: map[string]any{
					"login": "alice",
					"admin": true,
				},
			},
		})
		afterCreate := time.Now()
		require.NoError(err)
		require.NotNil(created)
		assert.Equal(user.ID, created.User)
		assert.Equal("github", created.Provider)
		assert.Equal("alice-123", created.Sub)
		assert.Equal("alice@users.noreply.github.com", created.Email)
		assert.Equal("alice", created.Claims["login"])
		assert.Equal(true, created.Claims["admin"])
		assert.WithinDuration(afterCreate, created.CreatedAt, 2*time.Second)
		assert.WithinDuration(afterCreate, created.ModifiedAt, 2*time.Second)
		assert.False(created.CreatedAt.Before(beforeCreate.Add(-2 * time.Second)))
		assert.False(created.ModifiedAt.Before(created.CreatedAt))

		fetched, err := m.GetIdentity(context.Background(), "github", "alice-123")
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal(created.User, fetched.User)
		assert.Equal(created.Email, fetched.Email)
		assert.Equal(created.Claims, fetched.Claims)
		assert.Equal(created.CreatedAt, fetched.CreatedAt)
		assert.Equal(created.ModifiedAt, fetched.ModifiedAt)

		fetchedUser, err := m.GetUser(context.Background(), user.ID)
		require.NoError(err)
		require.NotNil(fetchedUser)
		assert.Equal("alice", fetchedUser.Claims["login"])
		assert.Equal(true, fetchedUser.Claims["admin"])

		time.Sleep(10 * time.Millisecond)
		beforeUpdate := time.Now()
		updated, err := m.UpdateIdentity(context.Background(), "github", "alice-123", schema.IdentityMeta{
			Email: "alice.updated@users.noreply.github.com",
			Claims: map[string]any{
				"login": "alice-updated",
				"admin": false,
			},
		})
		afterUpdate := time.Now()
		require.NoError(err)
		require.NotNil(updated)
		assert.Equal(created.User, updated.User)
		assert.Equal(created.CreatedAt, updated.CreatedAt)
		assert.Equal("alice.updated@users.noreply.github.com", updated.Email)
		assert.Equal("alice-updated", updated.Claims["login"])
		assert.Equal(false, updated.Claims["admin"])
		assert.WithinDuration(afterUpdate, updated.ModifiedAt, 2*time.Second)
		assert.False(updated.ModifiedAt.Before(beforeUpdate.Add(-2 * time.Second)))
		assert.True(updated.ModifiedAt.After(created.ModifiedAt))

		updatedUser, err := m.GetUser(context.Background(), user.ID)
		require.NoError(err)
		require.NotNil(updatedUser)
		assert.Equal("alice-updated", updatedUser.Claims["login"])
		assert.Equal(false, updatedUser.Claims["admin"])

		deleted, err := m.DeleteIdentity(context.Background(), "github", "alice-123")
		require.NoError(err)
		require.NotNil(deleted)
		assert.Equal(updated.User, deleted.User)
		assert.Equal(updated.Provider, deleted.Provider)
		assert.Equal(updated.Sub, deleted.Sub)
		assert.Equal(updated.Email, deleted.Email)
		assert.Equal(updated.Claims, deleted.Claims)
		assert.Equal(updated.CreatedAt, deleted.CreatedAt)
		assert.Equal(updated.ModifiedAt, deleted.ModifiedAt)

		_, err = m.GetIdentity(context.Background(), "github", "alice-123")
		require.Error(err)
		assert.True(errors.Is(err, auth.ErrNotFound))

		userWithoutClaims, err := m.GetUser(context.Background(), user.ID)
		require.NoError(err)
		require.NotNil(userWithoutClaims)
		assert.Empty(userWithoutClaims.Claims)
	})

	t.Run("CreateMissingProvider", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Missing Provider",
			Email: "missing.provider@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(user)

		created, err := m.CreateIdentity(context.Background(), uuid.UUID(user.ID), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "",
				Sub:      "subject-1",
			},
		})
		require.Error(err)
		assert.Nil(created)
		assert.EqualError(err, "bad parameter: provider is required")
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("CreateMissingUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		created, err := m.CreateIdentity(context.Background(), uuid.New(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "github",
				Sub:      "missing-user",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "missing.user@users.noreply.github.com",
				Claims: map[string]any{
					"login": "missing-user",
				},
			},
		})
		require.Error(err)
		assert.Nil(created)

		_, err = m.GetIdentity(context.Background(), "github", "missing-user")
		require.Error(err)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("GetMissingIdentity", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		identity, err := m.GetIdentity(context.Background(), "github", "does-not-exist")
		require.Error(err)
		assert.Nil(identity)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})
}
