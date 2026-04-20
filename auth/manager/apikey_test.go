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
	schema "github.com/mutablelogic/go-auth/auth/schema"
	test "github.com/mutablelogic/go-auth/auth/test"
	require "github.com/stretchr/testify/require"
)

func Test_apikey_001(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)
	require.NotNil(t, manager)

	// Create a user
	user, err := manager.CreateUser(ctx, schema.UserMeta{
		Name:  "test-user",
		Email: "test-user@example.com",
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, user)

	t.Cleanup(func() {
		deleted, err := manager.DeleteUser(ctx, user.ID)
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

		t.Run("RejectsDuplicateNameForSameUser", func(t *testing.T) {
			duplicate, err := manager.CreateKey(ctx, user.ID, schema.KeyMeta{
				Name: "test-key",
			})
			require.Error(t, err)
			require.Nil(t, duplicate)
		})

		t.Run("GetCreatedKey", func(t *testing.T) {
			lookupKey, lookupUser, err := manager.GetKey(ctx, key.Token)
			require.NoError(t, err)
			require.NotNil(t, lookupKey)
			require.NotNil(t, lookupUser)
			require.Equal(t, user.ID, lookupKey.User)
			require.Equal(t, key.Name, lookupKey.Name)
			require.Equal(t, user.ID, lookupUser.ID)
			require.Equal(t, user.Email, lookupUser.Email)
			require.Empty(t, lookupKey.Token)
		})

		t.Run("RejectsInvalidKey", func(t *testing.T) {
			lookupKey, lookupUser, err := manager.GetKey(ctx, "invalid-key")
			require.Error(t, err)
			require.Nil(t, lookupKey)
			require.Nil(t, lookupUser)
		})
	})
}

func Test_apikey_002(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)
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
	defer test.End(t)
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
