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
	"strings"
	"testing"
	"time"

	// Packages
	uuid "github.com/google/uuid"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	test "github.com/mutablelogic/go-auth/auth/test"
	require "github.com/stretchr/testify/require"
)

func Test_apikey_001(t *testing.T) {
	manager, ctx := test.Begin(t)
	require.NotNil(t, manager)

	// Create a user
	user, err := manager.CreateUser(ctx, schema.UserMeta{
		Name:  "test-user",
		Email: "test-user@example.com",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, user)

	otherUser, err := manager.CreateUser(ctx, schema.UserMeta{
		Name:  "other-user",
		Email: "other-user@example.com",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, otherUser)

	t.Cleanup(func() {
		deleted, err := manager.DeleteUser(ctx, user.ID)
		require.NoError(t, err)
		require.NotNil(t, deleted)

		deleted, err = manager.DeleteUser(ctx, otherUser.ID)
		require.NoError(t, err)
		require.NotNil(t, deleted)
	})

	t.Run("CreateKey", func(t *testing.T) {
		key, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{
			Name: "test-key",
		})
		require.NoError(t, err)
		require.NotNil(t, key)

		t.Run("ReturnsGeneratedFields", func(t *testing.T) {
			require.NotEqual(t, schema.KeyID(uuid.Nil), key.ID)
			require.Equal(t, user.ID, key.User)
			require.Equal(t, "test-key", key.Name)
			require.NotEmpty(t, key.Token)
			require.True(t, strings.HasPrefix(key.Token, apiKeyPrefix))
			require.False(t, key.CreatedAt.IsZero())
			require.False(t, key.ModifiedAt.IsZero())
		})

		t.Run("OmitsUnsetUserFields", func(t *testing.T) {
			require.Nil(t, key.ExpiresAt)
			require.Nil(t, key.Status)
		})

		t.Run("GetCreatedKeyByID", func(t *testing.T) {
			lookupKey, err := manager.GetKeyByID(ctx, key.ID, &user.ID)
			require.NoError(t, err)
			require.NotNil(t, lookupKey)
			require.Equal(t, key.ID, lookupKey.ID)
			require.Equal(t, user.ID, lookupKey.User)
			require.Equal(t, key.Name, lookupKey.Name)
			require.Empty(t, lookupKey.Token)
		})

		t.Run("GetCreatedKeyByIDWithoutUserScope", func(t *testing.T) {
			lookupKey, err := manager.GetKeyByID(ctx, key.ID, nil)
			require.NoError(t, err)
			require.NotNil(t, lookupKey)
			require.Equal(t, key.ID, lookupKey.ID)
			require.Equal(t, user.ID, lookupKey.User)
		})

		t.Run("RejectsGetKeyByIDForWrongUser", func(t *testing.T) {
			lookupKey, err := manager.GetKeyByID(ctx, key.ID, &otherUser.ID)
			require.Error(t, err)
			require.Nil(t, lookupKey)
		})

		t.Run("RejectsDuplicateNameForSameUser", func(t *testing.T) {
			duplicate, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{
				Name: "test-key",
			})
			require.Error(t, err)
			require.Nil(t, duplicate)
		})

		t.Run("AllowsSameNameForDifferentUser", func(t *testing.T) {
			duplicate, err := manager.CreateKey(ctx, otherUser.ID, schema.KeyMeta{
				Name: "test-key",
			})
			require.NoError(t, err)
			require.NotNil(t, duplicate)
			require.Equal(t, otherUser.ID, duplicate.User)

			deleted, err := manager.DeleteKey(ctx, duplicate.ID, nil)
			require.NoError(t, err)
			require.NotNil(t, deleted)
		})

		t.Run("GetCreatedKeyByToken", func(t *testing.T) {
			lookupKey, lookupUser, err := manager.GetKeyByToken(ctx, key.Token)
			require.NoError(t, err)
			require.NotNil(t, lookupKey)
			require.NotNil(t, lookupUser)
			require.Equal(t, user.ID, lookupKey.User)
			require.Equal(t, key.Name, lookupKey.Name)
			require.Equal(t, user.ID, lookupUser.ID)
			require.Equal(t, user.Email, lookupUser.Email)
			require.Empty(t, lookupKey.Token)
		})

		t.Run("UpdateKey", func(t *testing.T) {
			expiresAt := time.Now().Add(12 * time.Hour).UTC().Truncate(time.Microsecond)
			updated, err := manager.UpdateKey(ctx, key.ID, &user.ID, schema.KeyMeta{
				Name:      "test-key-updated",
				ExpiresAt: &expiresAt,
			})
			require.NoError(t, err)
			require.NotNil(t, updated)
			require.Equal(t, key.ID, updated.ID)
			require.Equal(t, "test-key-updated", updated.Name)
			require.NotNil(t, updated.ExpiresAt)
			require.WithinDuration(t, expiresAt, *updated.ExpiresAt, time.Second)
		})

		t.Run("UpdateKeyWithoutUserScope", func(t *testing.T) {
			updated, err := manager.UpdateKey(ctx, key.ID, nil, schema.KeyMeta{Name: "test-key-unscoped"})
			require.NoError(t, err)
			require.NotNil(t, updated)
			require.Equal(t, key.ID, updated.ID)
			require.Equal(t, "test-key-unscoped", updated.Name)
		})

		t.Run("RejectsUpdateKeyForWrongUser", func(t *testing.T) {
			updated, err := manager.UpdateKey(ctx, key.ID, &otherUser.ID, schema.KeyMeta{Name: "wrong-owner"})
			require.Error(t, err)
			require.Nil(t, updated)

			lookupKey, err := manager.GetKeyByID(ctx, key.ID, nil)
			require.NoError(t, err)
			require.NotNil(t, lookupKey)
			require.Equal(t, "test-key-unscoped", lookupKey.Name)
		})

		t.Run("ClearsExpiryWhenZeroTimeProvided", func(t *testing.T) {
			zero := time.Time{}
			updated, err := manager.UpdateKey(ctx, key.ID, &user.ID, schema.KeyMeta{ExpiresAt: &zero})
			require.NoError(t, err)
			require.NotNil(t, updated)
			require.Nil(t, updated.ExpiresAt)
		})

		t.Run("RejectsUpdateKeyWithoutPatch", func(t *testing.T) {
			updated, err := manager.UpdateKey(ctx, key.ID, &user.ID, schema.KeyMeta{})
			require.Error(t, err)
			require.Nil(t, updated)
		})

		t.Run("RejectsUpdateKeyWithoutPatchWhenUnscoped", func(t *testing.T) {
			updated, err := manager.UpdateKey(ctx, key.ID, nil, schema.KeyMeta{})
			require.Error(t, err)
			require.Nil(t, updated)
		})

		t.Run("RejectsDeleteKeyForWrongUser", func(t *testing.T) {
			protectedKey, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{Name: "protected-key"})
			require.NoError(t, err)
			require.NotNil(t, protectedKey)

			deleted, err := manager.DeleteKey(ctx, protectedKey.ID, &otherUser.ID)
			require.Error(t, err)
			require.Nil(t, deleted)

			lookupKey, err := manager.GetKeyByID(ctx, protectedKey.ID, &user.ID)
			require.NoError(t, err)
			require.NotNil(t, lookupKey)

			deleted, err = manager.DeleteKey(ctx, protectedKey.ID, &user.ID)
			require.NoError(t, err)
			require.NotNil(t, deleted)
		})

		t.Run("DeleteKey", func(t *testing.T) {
			deleted, err := manager.DeleteKey(ctx, key.ID, &user.ID)
			require.NoError(t, err)
			require.NotNil(t, deleted)
			require.Equal(t, key.ID, deleted.ID)

			lookupKey, err := manager.GetKeyByID(ctx, key.ID, &user.ID)
			require.Error(t, err)
			require.Nil(t, lookupKey)

			lookupTokenKey, lookupUser, err := manager.GetKeyByToken(ctx, key.Token)
			require.Error(t, err)
			require.Nil(t, lookupTokenKey)
			require.Nil(t, lookupUser)
		})

		t.Run("DeleteKeyWithoutUserScope", func(t *testing.T) {
			unscopedKey, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{Name: "unscoped-key"})
			require.NoError(t, err)
			require.NotNil(t, unscopedKey)

			deleted, err := manager.DeleteKey(ctx, unscopedKey.ID, nil)
			require.NoError(t, err)
			require.NotNil(t, deleted)
			require.Equal(t, unscopedKey.ID, deleted.ID)
		})

		t.Run("RejectsInvalidKeyToken", func(t *testing.T) {
			lookupKey, lookupUser, err := manager.GetKeyByToken(ctx, "invalid-key")
			require.Error(t, err)
			require.Nil(t, lookupKey)
			require.Nil(t, lookupUser)
		})
	})
}

func Test_apikey_002(t *testing.T) {
	manager, ctx := test.Begin(t)
	require.NotNil(t, manager)

	userExpiresAt := time.Now().Add(-1 * time.Hour).UTC().Truncate(time.Microsecond)
	user, err := manager.CreateUser(ctx, schema.UserMeta{
		Name:      "expired-user",
		Email:     "expired-user@example.com",
		ExpiresAt: &userExpiresAt,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, user)

	t.Cleanup(func() {
		deleted, err := manager.DeleteUser(ctx, user.ID)
		require.NoError(t, err)
		require.NotNil(t, deleted)
	})

	keyExpiresAt := time.Now().Add(24 * time.Hour).UTC().Truncate(time.Microsecond)
	key, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{
		Name:      "expired-key",
		ExpiresAt: &keyExpiresAt,
	})
	require.NoError(t, err)
	require.NotNil(t, key)
	require.NotNil(t, key.ExpiresAt)
	require.WithinDuration(t, userExpiresAt, *key.ExpiresAt, time.Second)
}

func Test_apikey_003(t *testing.T) {
	manager, ctx := test.Begin(t)
	require.NotNil(t, manager)

	status := schema.UserStatusSuspended
	user, err := manager.CreateUser(ctx, schema.UserMeta{
		Name:   "status-user",
		Email:  "status-user@example.com",
		Status: &status,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, user)

	t.Cleanup(func() {
		deleted, err := manager.DeleteUser(ctx, user.ID)
		require.NoError(t, err)
		require.NotNil(t, deleted)
	})

	key, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{
		Name: "status-key",
	})
	require.NoError(t, err)
	require.NotNil(t, key)
	require.NotNil(t, key.Status)
	require.Equal(t, status, *key.Status)
}
