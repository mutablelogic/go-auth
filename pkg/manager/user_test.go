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
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// HELPERS

type emailCountSelector struct {
	Email string
}

type countResult struct {
	Value int
}

func (selector emailCountSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("email", selector.Email)
	return `SELECT COUNT(*) FROM auth.user WHERE email = @email`, nil
}

func (result *countResult) Scan(row pg.Row) error {
	return row.Scan(&result.Value)
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func Test_user_001(t *testing.T) {
	t.Run("CreateWithIdentityRollback", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		email := "rollback@example.com"

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Rollback User",
			Email: email,
		}, &schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "",
				Sub:      "rollback-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "rollback@users.noreply.github.com",
			},
		})
		require.Error(err)
		assert.Nil(created)
		assert.EqualError(err, "bad parameter: provider is required")
		assert.True(errors.Is(err, auth.ErrBadParameter))

		var count countResult
		require.NoError(m.Get(context.Background(), &count, emailCountSelector{Email: email}))
		assert.Zero(count.Value)
	})

	t.Run("CreateWithIdentity", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		beforeCreate := time.Now()

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Alice With Identity",
			Email: "  Alice@Example.COM  ",
		}, &schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "github",
				Sub:      "alice-identity",
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
		assert.NotZero(created.ID)
		assert.Equal("Alice With Identity", created.Name)
		assert.Equal("alice@example.com", created.Email)
		assert.Equal("alice", created.Claims["login"])
		assert.Equal(true, created.Claims["admin"])
		assert.WithinDuration(afterCreate, created.CreatedAt, 2*time.Second)
		assert.Nil(created.ModifiedAt)
		assert.False(created.CreatedAt.Before(beforeCreate.Add(-2 * time.Second)))
		assert.Empty(created.Groups)
		assert.Empty(created.Scopes)

		identity, err := m.GetIdentity(context.Background(), "github", "alice-identity")
		require.NoError(err)
		require.NotNil(identity)
		assert.Equal(created.ID, identity.User)
		assert.Equal("alice@users.noreply.github.com", identity.Email)
		assert.Equal("alice", identity.Claims["login"])
		assert.Equal(true, identity.Claims["admin"])
		assert.Equal("github", identity.Provider)
		assert.Equal("alice-identity", identity.Sub)

		fetched, err := m.GetUser(context.Background(), created.ID)
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal(created.ID, fetched.ID)
		assert.Equal(created.Email, fetched.Email)
		assert.Equal(created.Claims, fetched.Claims)
		assert.Nil(fetched.ModifiedAt)
	})

	t.Run("CreateGetUpdateDelete", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		beforeCreate := time.Now()

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Alice Example",
			Email:  "  Alice@Example.COM  ",
			Status: types.Ptr(schema.UserStatusActive),
			Meta: map[string]any{
				"team": "auth",
			},
		}, nil)
		afterCreate := time.Now()
		require.NoError(err)
		require.NotNil(created)
		assert.NotZero(created.ID)
		assert.Equal("Alice Example", created.Name)
		assert.Equal("alice@example.com", created.Email)
		assert.Equal(types.Ptr(schema.UserStatusActive), created.Status)
		assert.Equal("auth", created.Meta["team"])
		assert.WithinDuration(afterCreate, created.CreatedAt, 2*time.Second)
		assert.Nil(created.ModifiedAt)
		assert.False(created.CreatedAt.Before(beforeCreate.Add(-2 * time.Second)))
		assert.Empty(created.Claims)
		assert.Empty(created.Groups)
		assert.Empty(created.Scopes)

		fetched, err := m.GetUser(context.Background(), created.ID)
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal(created.ID, fetched.ID)
		assert.Equal(created.Email, fetched.Email)
		assert.Equal(created.Meta, fetched.Meta)
		assert.Equal(created.CreatedAt, fetched.CreatedAt)
		assert.Nil(fetched.ModifiedAt)

		time.Sleep(10 * time.Millisecond)
		beforeUpdate := time.Now()

		updated, err := m.UpdateUser(context.Background(), created.ID, schema.UserMeta{
			Name:  "Alice Updated",
			Email: "  Alice.Updated@Example.COM  ",
			Meta: map[string]any{
				"team":  "platform",
				"admin": true,
			},
		})
		afterUpdate := time.Now()
		require.NoError(err)
		require.NotNil(updated)
		assert.Equal(created.ID, updated.ID)
		assert.Equal("Alice Updated", updated.Name)
		assert.Equal("alice.updated@example.com", updated.Email)
		assert.Equal("platform", updated.Meta["team"])
		assert.Equal(true, updated.Meta["admin"])
		assert.Equal(created.CreatedAt, updated.CreatedAt)
		require.NotNil(updated.ModifiedAt)
		assert.WithinDuration(afterUpdate, *updated.ModifiedAt, 2*time.Second)
		assert.False(updated.ModifiedAt.Before(beforeUpdate.Add(-2 * time.Second)))

		deleted, err := m.DeleteUser(context.Background(), created.ID)
		require.NoError(err)
		require.NotNil(deleted)
		assert.Equal(created.ID, deleted.ID)
		assert.Equal(updated.Email, deleted.Email)
		assert.Equal(updated.CreatedAt, deleted.CreatedAt)
		assert.Equal(updated.ModifiedAt, deleted.ModifiedAt)

		_, err = m.GetUser(context.Background(), created.ID)
		require.Error(err)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("GetMissingUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		user, err := m.GetUser(context.Background(), schema.UserID(uuid.New()))
		require.Error(err)
		assert.Nil(user)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("CreateDuplicateCanonicalEmail", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		first, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "First User",
			Email: "  Alice@Example.COM  ",
		}, nil)
		require.NoError(err)
		require.NotNil(first)
		assert.Equal("alice@example.com", first.Email)

		second, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Second User",
			Email: "alice@example.com",
		}, nil)
		require.Error(err)
		assert.Nil(second)
		assert.True(errors.Is(err, auth.ErrConflict))

		var count countResult
		require.NoError(m.Get(context.Background(), &count, emailCountSelector{Email: "alice@example.com"}))
		assert.Equal(1, count.Value)
	})

	t.Run("ListUsers", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		active := schema.UserStatusActive
		inactive := schema.UserStatusInactive

		fixtures := []schema.UserMeta{
			{Name: "Alpha", Email: "  alpha@example.com  ", Status: &active},
			{Name: "Bravo", Email: "  bravo@example.com  ", Status: &inactive},
			{Name: "Charlie", Email: "  charlie@example.com  ", Status: &active},
			{Name: "Delta", Email: "  delta@example.com  "},
		}
		for _, fixture := range fixtures {
			created, err := m.CreateUser(context.Background(), fixture, nil)
			require.NoError(err)
			require.NotNil(created)
		}

		limit := uint64(2)
		paged, err := m.ListUsers(context.Background(), schema.UserListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit},
		})
		require.NoError(err)
		require.NotNil(paged)
		assert.Equal(uint(4), paged.Count)
		assert.Equal(uint64(1), paged.Offset)
		require.NotNil(paged.Limit)
		assert.Equal(uint64(2), *paged.Limit)
		require.Len(paged.Body, 2)
		assert.Equal("bravo@example.com", paged.Body[0].Email)
		assert.Equal("charlie@example.com", paged.Body[1].Email)

		filteredByEmail, err := m.ListUsers(context.Background(), schema.UserListRequest{
			Email: "  CHARLIE@EXAMPLE.COM  ",
		})
		require.NoError(err)
		require.NotNil(filteredByEmail)
		assert.Equal(uint(1), filteredByEmail.Count)
		require.Len(filteredByEmail.Body, 1)
		assert.Equal("charlie@example.com", filteredByEmail.Body[0].Email)

		filteredByStatus, err := m.ListUsers(context.Background(), schema.UserListRequest{
			Status: []schema.UserStatus{schema.UserStatusActive},
		})
		require.NoError(err)
		require.NotNil(filteredByStatus)
		assert.Equal(uint(2), filteredByStatus.Count)
		require.Len(filteredByStatus.Body, 2)
		assert.Equal("alpha@example.com", filteredByStatus.Body[0].Email)
		assert.Equal("charlie@example.com", filteredByStatus.Body[1].Email)
		assert.Equal(types.Ptr(schema.UserStatusActive), filteredByStatus.Body[0].Status)
		assert.Equal(types.Ptr(schema.UserStatusActive), filteredByStatus.Body[1].Status)

		largeLimit := uint64(10)
		clamped, err := m.ListUsers(context.Background(), schema.UserListRequest{
			OffsetLimit: pg.OffsetLimit{Limit: &largeLimit},
		})
		require.NoError(err)
		require.NotNil(clamped)
		assert.Equal(uint(4), clamped.Count)
		require.NotNil(clamped.Limit)
		assert.Equal(uint64(4), *clamped.Limit)
		require.Len(clamped.Body, 4)
	})

	t.Run("CreateInvalidEmail", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Broken Email",
			Email: "not-an-email",
		}, nil)
		require.Error(err)
		assert.Nil(created)
		assert.EqualError(err, `bad parameter: invalid email address "not-an-email"`)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})
}
