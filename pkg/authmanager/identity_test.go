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
	manager "github.com/mutablelogic/go-auth/pkg/authmanager"
	schema "github.com/mutablelogic/go-auth/schema/auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	attribute "go.opentelemetry.io/otel/attribute"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

type testCreateHook struct{}

func (testCreateHook) OnUserCreate(ctx context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
	status := schema.UserStatusNew
	meta.Status = &status
	meta.Meta = map[string]any{"source": identity.Provider}
	return meta, nil
}

type testRejectCreateHook struct{ err error }

func (h testRejectCreateHook) OnUserCreate(ctx context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
	return schema.UserMeta{}, h.err
}

type testCalledCreateHook struct{ called *bool }

func (h testCalledCreateHook) OnUserCreate(ctx context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
	*h.called = true
	return meta, nil
}

type testLinkHook struct{ called *bool }

func (h testLinkHook) OnIdentityLink(ctx context.Context, identity schema.IdentityInsert, existing *schema.User) error {
	*h.called = true
	return nil
}

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

	t.Run("ListIdentitiesTracing", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		exporter := tracetest.NewInMemoryExporter()
		provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
		defer func() {
			require.NoError(provider.Shutdown(context.Background()))
		}()

		m := newTestManagerWithOpts(t, manager.WithTracer(provider.Tracer("manager-identity-test")))

		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Trace Identity User",
			Email: "trace.identity@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(user)

		created, err := m.CreateIdentity(context.Background(), uuid.UUID(user.ID), schema.IdentityInsert{
			IdentityKey:  schema.IdentityKey{Provider: "github", Sub: "trace-identity"},
			IdentityMeta: schema.IdentityMeta{Email: "trace@github.example.com"},
		})
		require.NoError(err)
		require.NotNil(created)

		userID := uuid.UUID(user.ID)
		req := schema.IdentityListRequest{User: &userID}
		expectedRequest := req.String()

		listed, err := m.ListIdentities(context.Background(), req)
		require.NoError(err)
		require.NotNil(listed)

		require.NoError(provider.ForceFlush(context.Background()))
		spans := exporter.GetSpans()

		var listIdentitiesSpan *tracetest.SpanStub
		for i := range spans {
			if spans[i].Name == "manager.ListIdentities" {
				listIdentitiesSpan = &spans[i]
				break
			}
		}
		require.NotNil(listIdentitiesSpan)
		assert.Contains(listIdentitiesSpan.Attributes, attribute.String("request", expectedRequest))
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
					"login":  "alice",
					"admin":  true,
					"role":   "staff",
					"region": "eu",
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

		fetched, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "alice-123"})
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
		assert.Equal("staff", fetchedUser.Claims["role"])
		assert.Equal("eu", fetchedUser.Claims["region"])

		time.Sleep(10 * time.Millisecond)
		beforeUpdate := time.Now()
		updated, err := m.UpdateIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "alice-123"}, schema.IdentityMeta{
			Email: "alice.updated@users.noreply.github.com",
			Claims: map[string]any{
				"login":  "alice-updated",
				"admin":  false,
				"region": nil,
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
		assert.Equal("staff", updated.Claims["role"])
		_, hasRegion := updated.Claims["region"]
		assert.False(hasRegion)
		assert.WithinDuration(afterUpdate, updated.ModifiedAt, 2*time.Second)
		assert.False(updated.ModifiedAt.Before(beforeUpdate.Add(-2 * time.Second)))
		assert.True(updated.ModifiedAt.After(created.ModifiedAt))

		updatedUser, err := m.GetUser(context.Background(), user.ID)
		require.NoError(err)
		require.NotNil(updatedUser)
		assert.Equal("alice-updated", updatedUser.Claims["login"])
		assert.Equal(false, updatedUser.Claims["admin"])
		assert.Equal("staff", updatedUser.Claims["role"])
		_, hasRegion = updatedUser.Claims["region"]
		assert.False(hasRegion)

		deleted, err := m.DeleteIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "alice-123"})
		require.NoError(err)
		require.NotNil(deleted)
		assert.Equal(updated.User, deleted.User)
		assert.Equal(updated.Provider, deleted.Provider)
		assert.Equal(updated.Sub, deleted.Sub)
		assert.Equal(updated.Email, deleted.Email)
		assert.Equal(updated.Claims, deleted.Claims)
		assert.Equal(updated.CreatedAt, deleted.CreatedAt)
		assert.Equal(updated.ModifiedAt, deleted.ModifiedAt)

		_, err = m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "alice-123"})
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

		_, err = m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "missing-user"})
		require.Error(err)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("GetMissingIdentity", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "github", Sub: "does-not-exist"})
		require.Error(err)
		assert.Nil(identity)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("LoginWithIdentity", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Login Identity User",
			Email: "login.identity@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(user)

		_, err = m.CreateIdentity(context.Background(), uuid.UUID(user.ID), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "google-sub-123",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "old@example.com",
				Claims: map[string]any{
					"name": "Old Name",
				},
			},
		})
		require.NoError(err)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "google-sub-123",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "new@example.com",
				Claims: map[string]any{
					"name":  "New Name",
					"email": "new@example.com",
				},
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		assert.Equal(user.ID, loggedIn.ID)
		assert.Equal(loggedIn.ID, session.User)
		assert.Equal("login.identity@example.com", loggedIn.Email)
		assert.Equal("New Name", loggedIn.Claims["name"])
		assert.Equal("new@example.com", loggedIn.Claims["email"])

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "https://accounts.google.com", Sub: "google-sub-123"})
		require.NoError(err)
		require.NotNil(identity)
		assert.Equal("new@example.com", identity.Email)
		assert.Equal("New Name", identity.Claims["name"])
	})

	t.Run("LoginWithMissingIdentity", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "missing-sub",
			},
		}, nil)
		require.Error(err)
		assert.Nil(loggedIn)
		assert.Nil(session)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})

	t.Run("LoginWithIdentityCreatesUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "new-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "new.user@example.com",
				Claims: map[string]any{
					"name": "New User",
				},
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		assert.Equal("new.user@example.com", loggedIn.Email)
		assert.Equal("New User", loggedIn.Name)
		assert.Equal("New User", loggedIn.Claims["name"])
		assert.Equal(loggedIn.ID, session.User)

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "https://accounts.google.com", Sub: "new-subject"})
		require.NoError(err)
		require.NotNil(identity)
		assert.Equal(loggedIn.ID, identity.User)
		assert.Equal("new.user@example.com", identity.Email)
	})

	t.Run("LoginWithIdentityCreatesUserWithHook", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t, manager.WithHooks(testCreateHook{}))

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "hooked-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "hooked.user@example.com",
				Claims: map[string]any{
					"name": "Hooked User",
				},
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		require.NotNil(loggedIn.Status)
		assert.Equal(schema.UserStatusNew, *loggedIn.Status)
		assert.Equal("https://accounts.google.com", loggedIn.Meta["source"])
		assert.Equal(loggedIn.ID, session.User)
	})

	t.Run("LoginWithIdentityUserHookRejectsNewUser", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		expected := errors.New("signup blocked")

		m := newTestManagerWithOpts(t, manager.WithHooks(testRejectCreateHook{err: expected}))

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "blocked-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "blocked.user@example.com",
			},
		}, nil)
		require.Error(err)
		assert.Nil(loggedIn)
		assert.Nil(session)
		assert.ErrorIs(err, expected)

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "https://accounts.google.com", Sub: "blocked-subject"})
		require.Error(err)
		assert.Nil(identity)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("LoginWithIdentitySkipsUserHookForExistingIdentity", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		called := false
		m := newTestManagerWithOpts(t, manager.WithHooks(testCalledCreateHook{called: &called}))

		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Existing Hook User",
			Email: "existing.hook.user@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(user)

		_, err = m.CreateIdentity(context.Background(), uuid.UUID(user.ID), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "existing-hook-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "existing.identity@example.com",
			},
		})
		require.NoError(err)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "existing-hook-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "updated.identity@example.com",
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		assert.False(called)
	})

	t.Run("LoginWithIdentityLinksExistingUserWithHook", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		called := false
		m := newTestManagerWithOpts(t, manager.WithHooks(testLinkHook{called: &called}))

		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Linked User",
			Email: "linked.user@example.com",
		}, nil)
		require.NoError(err)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://login.microsoftonline.com/example",
				Sub:      "linked-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email:  "linked.user@example.com",
				Claims: map[string]any{"name": "Linked User"},
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		assert.True(called)
		assert.Equal(user.ID, loggedIn.ID)

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "https://login.microsoftonline.com/example", Sub: "linked-subject"})
		require.NoError(err)
		assert.Equal(user.ID, identity.User)
	})

	t.Run("LoginWithIdentityUsesPreferredUsername", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "preferred-username-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "preferred.user@example.com",
				Claims: map[string]any{
					"preferred_username": "preferred-user",
				},
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		assert.Equal("preferred-user", loggedIn.Name)
		assert.Equal(loggedIn.ID, session.User)
	})

	t.Run("LoginWithIdentityUsesGivenName", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "given-family-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "given.family@example.com",
				Claims: map[string]any{
					"given_name":  "Given",
					"family_name": "Ignored",
				},
			},
		}, nil)
		require.NoError(err)
		require.NotNil(loggedIn)
		require.NotNil(session)
		assert.Equal("Given", loggedIn.Name)
		assert.Equal(loggedIn.ID, session.User)
	})

	t.Run("LoginWithIdentityRejectsExistingEmail", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		user, err := m.CreateUser(context.Background(), schema.UserMeta{
			Name:  "Existing User",
			Email: "existing.user@example.com",
		}, nil)
		require.NoError(err)
		require.NotNil(user)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "unlinked-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Email: "existing.user@example.com",
			},
		}, nil)
		require.Error(err)
		assert.Nil(loggedIn)
		assert.Nil(session)
		assert.True(errors.Is(err, auth.ErrConflict))

		identity, err := m.GetIdentity(context.Background(), schema.IdentityKey{Provider: "https://accounts.google.com", Sub: "unlinked-subject"})
		require.Error(err)
		assert.Nil(identity)
		assert.True(errors.Is(err, auth.ErrNotFound))
	})

	t.Run("LoginWithIdentityCreateRequiresEmail", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)

		loggedIn, session, err := m.LoginWithIdentity(context.Background(), schema.IdentityInsert{
			IdentityKey: schema.IdentityKey{
				Provider: "https://accounts.google.com",
				Sub:      "no-email-subject",
			},
			IdentityMeta: schema.IdentityMeta{
				Claims: map[string]any{
					"name": "No Email",
				},
			},
		}, nil)
		require.Error(err)
		assert.Nil(loggedIn)
		assert.Nil(session)
		assert.True(errors.Is(err, auth.ErrBadParameter))
	})
}
