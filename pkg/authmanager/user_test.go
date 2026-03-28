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
	auth "github.com/djthorpe/go-auth"
	manager "github.com/djthorpe/go-auth/pkg/authmanager"
	schema "github.com/djthorpe/go-auth/schema/auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	attribute "go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

///////////////////////////////////////////////////////////////////////////////
// HELPERS

type emailCountSelector struct {
	Email string
}

type countResult struct {
	Value int
}

type userGroupListSelector struct {
	User schema.UserID
}

type userGroupListResult struct {
	Groups []string
}

func (selector emailCountSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("email", selector.Email)
	return `SELECT COUNT(*) FROM auth.user WHERE email = @email`, nil
}

func (result *countResult) Scan(row pg.Row) error {
	return row.Scan(&result.Value)
}

func (selector userGroupListSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("user", selector.User)
	return `SELECT "group" FROM auth.user_group WHERE "user" = @user ORDER BY "group" ASC`, nil
}

func (result *userGroupListResult) Scan(row pg.Row) error {
	var group string
	if err := row.Scan(&group); err != nil {
		return err
	}
	result.Groups = append(result.Groups, group)
	return nil
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

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "alice-identity"})
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

	t.Run("CreateWithGroupsRollback", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		email := "groups.rollback@example.com"

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Groups Rollback",
			Email:  email,
			Groups: []string{"missing_group"},
		}, nil)
		require.Error(err)
		assert.Nil(created)

		var count countResult
		require.NoError(m.Get(context.Background(), &count, emailCountSelector{Email: email}))
		assert.Zero(count.Value)
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
				"team":   "auth",
				"region": "eu",
				"tier":   "gold",
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
		assert.Equal("eu", created.Meta["region"])
		assert.Equal("gold", created.Meta["tier"])
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
				"team":   "platform",
				"admin":  true,
				"region": nil,
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
		assert.Equal("gold", updated.Meta["tier"])
		_, hasRegion := updated.Meta["region"]
		assert.False(hasRegion)
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

	t.Run("UserGroupsAndScopes", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		disabled := false
		_, err := m.CreateGroup(context.Background(), schema.GroupInsert{
			ID: "admins",
			GroupMeta: schema.GroupMeta{
				Enabled: &enabled,
				Scopes:  []string{"user.read", "user.write"},
				Meta:    schema.MetaMap{"group_admin": "hello", "team": "group-admins"},
			},
		})
		require.NoError(err)
		_, err = m.CreateGroup(context.Background(), schema.GroupInsert{
			ID: "staff",
			GroupMeta: schema.GroupMeta{
				Enabled: &enabled,
				Scopes:  []string{"profile.read", "user.read"},
				Meta:    schema.MetaMap{"team": "group-staff", "region": "eu"},
			},
		})
		require.NoError(err)
		_, err = m.CreateGroup(context.Background(), schema.GroupInsert{
			ID: "disabled_group",
			GroupMeta: schema.GroupMeta{
				Enabled: &disabled,
				Scopes:  []string{"admin.all"},
			},
		})
		require.NoError(err)

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Grouped User",
			Email:  "grouped.user@example.com",
			Meta:   schema.MetaMap{"team": "user", "source": "local"},
			Groups: []string{" admins ", "staff", "admins", "", "disabled_group"},
		}, nil)
		require.NoError(err)
		require.NotNil(created)
		assert.Equal("hello", created.EffectiveMeta["group_admin"])
		assert.Equal("eu", created.EffectiveMeta["region"])
		assert.Equal("user", created.EffectiveMeta["team"])
		assert.Equal("local", created.EffectiveMeta["source"])
		assert.Equal("user", created.Meta["team"])
		assert.Equal("local", created.Meta["source"])
		assert.Equal([]string{"disabled_group"}, created.DisabledGroups)

		fetched, err := m.GetUser(context.Background(), created.ID)
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal([]string{"admins", "staff"}, fetched.Groups)
		assert.Equal([]string{"profile.read", "user.read", "user.write"}, fetched.Scopes)
		assert.Equal("hello", fetched.EffectiveMeta["group_admin"])
		assert.Equal("eu", fetched.EffectiveMeta["region"])
		assert.Equal("user", fetched.EffectiveMeta["team"])
		assert.Equal("local", fetched.EffectiveMeta["source"])
		assert.Equal("user", fetched.Meta["team"])
		assert.Equal("local", fetched.Meta["source"])
		assert.Equal([]string{"disabled_group"}, fetched.DisabledGroups)

		updated, err := m.UpdateUser(context.Background(), created.ID, schema.UserMeta{
			Name:   "Grouped User Updated",
			Groups: []string{"staff"},
		})
		require.NoError(err)
		require.NotNil(updated)
		assert.Equal([]string{"staff"}, updated.Groups)
		assert.Equal([]string{"profile.read", "user.read"}, updated.Scopes)
		_, hasGroupAdmin := updated.EffectiveMeta["group_admin"]
		assert.False(hasGroupAdmin)
		assert.Equal("eu", updated.EffectiveMeta["region"])
		assert.Equal("user", updated.EffectiveMeta["team"])
		assert.Equal("local", updated.EffectiveMeta["source"])
		assert.Equal("user", updated.Meta["team"])
		assert.Equal("local", updated.Meta["source"])
		assert.Empty(updated.DisabledGroups)

		cleared, err := m.UpdateUser(context.Background(), created.ID, schema.UserMeta{Groups: []string{" ", ""}})
		require.NoError(err)
		require.NotNil(cleared)
		assert.Empty(cleared.Groups)
		assert.Empty(cleared.Scopes)
		assert.Equal("user", cleared.Meta["team"])
		assert.Equal("local", cleared.Meta["source"])
		assert.Empty(cleared.DisabledGroups)
		assert.Equal("user", cleared.EffectiveMeta["team"])
		assert.Equal("local", cleared.EffectiveMeta["source"])
		_, hasRegion := cleared.EffectiveMeta["region"]
		assert.False(hasRegion)

		listed, err := m.ListUsers(context.Background(), schema.UserListRequest{Email: created.Email})
		require.NoError(err)
		require.NotNil(listed)
		require.Len(listed.Body, 1)
		assert.Empty(listed.Body[0].Groups)
		assert.Empty(listed.Body[0].Scopes)
		assert.Empty(listed.Body[0].DisabledGroups)
		assert.Equal("user", listed.Body[0].Meta["team"])
		assert.Equal("local", listed.Body[0].Meta["source"])
		assert.Equal("user", listed.Body[0].EffectiveMeta["team"])
		assert.Equal("local", listed.Body[0].EffectiveMeta["source"])

		deleted, err := m.DeleteUser(context.Background(), created.ID)
		require.NoError(err)
		require.NotNil(deleted)
		assert.Empty(deleted.Groups)
		assert.Empty(deleted.Scopes)
		assert.Empty(deleted.DisabledGroups)
		assert.Equal("user", deleted.Meta["team"])
		assert.Equal("local", deleted.Meta["source"])
		assert.Equal("user", deleted.EffectiveMeta["team"])
		assert.Equal("local", deleted.EffectiveMeta["source"])
	})

	t.Run("UpdateWithGroupsRollback", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		_, err := m.CreateGroup(context.Background(), schema.GroupInsert{ID: "staff", GroupMeta: schema.GroupMeta{Enabled: &enabled, Scopes: []string{"profile.read"}}})
		require.NoError(err)

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Rollback Update User",
			Email:  "rollback.update@example.com",
			Groups: []string{"staff"},
		}, nil)
		require.NoError(err)
		require.NotNil(created)

		updated, err := m.UpdateUser(context.Background(), created.ID, schema.UserMeta{
			Name:   "Should Not Persist",
			Groups: []string{"missing_group"},
		})
		require.Error(err)
		assert.Nil(updated)

		fetched, err := m.GetUser(context.Background(), created.ID)
		require.NoError(err)
		require.NotNil(fetched)
		assert.Equal("Rollback Update User", fetched.Name)
		assert.Equal([]string{"staff"}, fetched.Groups)
		assert.Equal([]string{"profile.read"}, fetched.Scopes)
	})

	t.Run("AddAndRemoveUserGroups", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		disabled := false
		_, err := m.CreateGroup(context.Background(), schema.GroupInsert{ID: "admins", GroupMeta: schema.GroupMeta{Enabled: &enabled, Scopes: []string{"user.read", "user.write"}}})
		require.NoError(err)
		_, err = m.CreateGroup(context.Background(), schema.GroupInsert{ID: "staff", GroupMeta: schema.GroupMeta{Enabled: &enabled, Scopes: []string{"profile.read"}}})
		require.NoError(err)
		_, err = m.CreateGroup(context.Background(), schema.GroupInsert{ID: "disabled_group", GroupMeta: schema.GroupMeta{Enabled: &disabled, Scopes: []string{"admin.all"}}})
		require.NoError(err)

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Group Mutation User",
			Email:  "group.mutation@example.com",
			Groups: []string{"disabled_group"},
		}, nil)
		require.NoError(err)
		require.NotNil(created)
		assert.Empty(created.Groups)
		assert.Equal([]string{"disabled_group"}, created.DisabledGroups)
		assert.Empty(created.Scopes)

		added, err := m.AddUserGroups(context.Background(), created.ID, []string{" admins ", "staff", "admins", ""})
		require.NoError(err)
		require.NotNil(added)
		assert.Equal([]string{"admins", "staff"}, added.Groups)
		assert.Equal([]string{"disabled_group"}, added.DisabledGroups)
		assert.Equal([]string{"profile.read", "user.read", "user.write"}, added.Scopes)

		var raw userGroupListResult
		require.NoError(m.List(context.Background(), &raw, userGroupListSelector{User: created.ID}))
		assert.Equal([]string{"admins", "disabled_group", "staff"}, raw.Groups)

		_, err = m.UpdateGroup(context.Background(), "disabled_group", schema.GroupMeta{Enabled: &enabled})
		require.NoError(err)
		fetched, err := m.GetUser(context.Background(), created.ID)
		require.NoError(err)
		assert.Equal([]string{"admins", "disabled_group", "staff"}, fetched.Groups)
		assert.Empty(fetched.DisabledGroups)
		assert.Equal([]string{"admin.all", "profile.read", "user.read", "user.write"}, fetched.Scopes)

		removed, err := m.RemoveUserGroups(context.Background(), created.ID, []string{" staff ", "disabled_group", "missing"})
		require.NoError(err)
		require.NotNil(removed)
		assert.Equal([]string{"admins"}, removed.Groups)
		assert.Empty(removed.DisabledGroups)
		assert.Equal([]string{"user.read", "user.write"}, removed.Scopes)

		raw = userGroupListResult{}
		require.NoError(m.List(context.Background(), &raw, userGroupListSelector{User: created.ID}))
		assert.Equal([]string{"admins"}, raw.Groups)
	})

	t.Run("AddRemoveUserGroupsRollback", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		enabled := true
		_, err := m.CreateGroup(context.Background(), schema.GroupInsert{ID: "staff", GroupMeta: schema.GroupMeta{Enabled: &enabled, Scopes: []string{"profile.read"}}})
		require.NoError(err)

		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Rollback Mutations",
			Email:  "rollback.mutations@example.com",
			Groups: []string{"staff"},
		}, nil)
		require.NoError(err)

		added, err := m.AddUserGroups(context.Background(), created.ID, []string{"missing_group"})
		require.Error(err)
		assert.Nil(added)

		removed, err := m.RemoveUserGroups(context.Background(), created.ID, []string{"missing_group"})
		require.NoError(err)
		require.NotNil(removed)
		assert.Equal([]string{"staff"}, removed.Groups)

		fetched, err := m.GetUser(context.Background(), created.ID)
		require.NoError(err)
		assert.Equal([]string{"staff"}, fetched.Groups)
		assert.Equal([]string{"profile.read"}, fetched.Scopes)
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

	t.Run("ListUsersTracing", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		active := schema.UserStatusActive

		exporter := tracetest.NewInMemoryExporter()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() {
			require.NoError(provider.Shutdown(context.Background()))
		}()

		m := newTestManagerWithOpts(t, manager.WithTracer(provider.Tracer("manager-test")))
		created, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:   "Trace User",
			Email:  "trace@example.com",
			Status: &active,
		}, nil)
		require.NoError(err)
		require.NotNil(created)

		limit := uint64(5)
		req := schema.UserListRequest{
			Email: "trace@example.com",
			Status: []schema.UserStatus{
				schema.UserStatusActive,
			},
			OffsetLimit: pg.OffsetLimit{Offset: 0, Limit: &limit},
		}
		expectedRequest := req.RedactedString()

		listed, err := m.ListUsers(context.Background(), req)
		require.NoError(err)
		require.NotNil(listed)

		require.NoError(provider.ForceFlush(context.Background()))
		spans := exporter.GetSpans()

		var listUsersSpan *tracetest.SpanStub
		for i := range spans {
			if spans[i].Name == "manager.ListUsers" {
				listUsersSpan = &spans[i]
				break
			}
		}
		require.NotNil(listUsersSpan)
		assert.Contains(listUsersSpan.Attributes, attribute.String("request", expectedRequest))
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
