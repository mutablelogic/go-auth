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

package pg_test

import (
	"fmt"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential/pg"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	test "github.com/mutablelogic/go-auth/credential/pg/test"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

// keys returns the keys of the credentials in a list
func keys(list *schema.CredentialList) []string {
	result := []string{}
	for _, credential := range list.Body {
		result = append(result, credential.Key)
	}
	return result
}

func TestListCredentials(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)

	// Create credentials on a schema of their own, so the list is exact
	manager := test.IsolatedManager(t)
	list := func(req schema.CredentialListRequest) *schema.CredentialList {
		t.Helper()
		result, err := manager.ListCredentials(ctx, req)
		require.NoError(t, err)
		return result
	}

	t.Run("Empty", func(t *testing.T) {
		result := list(schema.CredentialListRequest{})
		assert.Zero(t, result.Count)
		assert.Empty(t, result.Body)
	})

	// Create credentials out of order, which are listed in key order
	for _, i := range []int{3, 0, 4, 1, 2} {
		mustCreate(t, ctx, manager, fmt.Sprintf("list_%d", i), fmt.Sprintf("secret-%d", i))
	}
	all := []string{"list_0", "list_1", "list_2", "list_3", "list_4"}

	t.Run("All", func(t *testing.T) {
		result := list(schema.CredentialListRequest{})
		assert.Equal(t, uint64(5), result.Count)
		assert.Equal(t, all, keys(result))
		for _, credential := range result.Body {
			assert.False(t, credential.UpdatedAt.IsZero(), credential.Key)
		}
	})

	t.Run("Limit", func(t *testing.T) {
		result := list(schema.CredentialListRequest{OffsetLimit: pg.OffsetLimit{Limit: types.Ptr(uint64(2))}})
		assert.Equal(t, uint64(5), result.Count)
		assert.Equal(t, all[:2], keys(result))
	})

	t.Run("Offset", func(t *testing.T) {
		result := list(schema.CredentialListRequest{OffsetLimit: pg.OffsetLimit{Offset: 2, Limit: types.Ptr(uint64(2))}})
		assert.Equal(t, uint64(5), result.Count)
		assert.Equal(t, all[2:4], keys(result))
		require.NotNil(t, result.Limit)
		assert.Equal(t, uint64(2), *result.Limit)
	})

	t.Run("OffsetNearEnd", func(t *testing.T) {
		// The limit is clamped to the credentials after the offset
		result := list(schema.CredentialListRequest{OffsetLimit: pg.OffsetLimit{Offset: 4, Limit: types.Ptr(uint64(10))}})
		assert.Equal(t, all[4:], keys(result))
		require.NotNil(t, result.Limit)
		assert.Equal(t, uint64(1), *result.Limit)
	})

	t.Run("PastEnd", func(t *testing.T) {
		result := list(schema.CredentialListRequest{OffsetLimit: pg.OffsetLimit{Offset: 10}})
		assert.Equal(t, uint64(5), result.Count)
		assert.Empty(t, result.Body)
		require.NotNil(t, result.Limit)
		assert.Zero(t, *result.Limit)
	})

	t.Run("LimitCapped", func(t *testing.T) {
		// The limit is capped, and the caller's limit is not modified
		limit := uint64(schema.CredentialListLimit + 1)
		result := list(schema.CredentialListRequest{OffsetLimit: pg.OffsetLimit{Limit: &limit}})
		assert.Equal(t, all, keys(result))
		require.NotNil(t, result.Limit)
		assert.LessOrEqual(t, *result.Limit, uint64(schema.CredentialListLimit))
		assert.Equal(t, uint64(schema.CredentialListLimit+1), limit)
	})
}

func TestListCredentialsRotate(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)

	// Credentials encrypted with passphrase version one, and then version
	// two, on a schema of their own
	schemaName := test.IsolatedSchema(t)
	v1 := test.SchemaManager(t, schemaName)
	v2 := test.SchemaManager(t, schemaName, credential.WithPassphrase(2, "second passphrase"))
	mustCreate(t, ctx, v1, "rotate_old_0", "old-0")
	mustCreate(t, ctx, v1, "rotate_old_1", "old-1")
	mustCreate(t, ctx, v2, "rotate_new_0", "new-0")
	mustCreate(t, ctx, v2, "rotate_new_1", "new-1")

	list := func(manager *credential.Manager, rotate *bool) (*schema.CredentialList, error) {
		return manager.ListCredentials(ctx, schema.CredentialListRequest{Rotate: rotate})
	}

	t.Run("NeedsRotation", func(t *testing.T) {
		// With version two the latest, the version one credentials need
		// rotating
		result, err := list(v2, types.Ptr(true))
		require.NoError(t, err)
		assert.Equal(t, uint64(2), result.Count)
		assert.Equal(t, []string{"rotate_old_0", "rotate_old_1"}, keys(result))
	})

	t.Run("Current", func(t *testing.T) {
		result, err := list(v2, types.Ptr(false))
		require.NoError(t, err)
		assert.Equal(t, uint64(2), result.Count)
		assert.Equal(t, []string{"rotate_new_0", "rotate_new_1"}, keys(result))
	})

	t.Run("LatestVersion", func(t *testing.T) {
		// Whether a credential needs rotating depends on the manager's latest
		// passphrase version: with version one the latest, the version two
		// credentials need rotating
		result, err := list(v1, types.Ptr(true))
		require.NoError(t, err)
		assert.Equal(t, []string{"rotate_new_0", "rotate_new_1"}, keys(result))
	})

	t.Run("All", func(t *testing.T) {
		result, err := list(v2, nil)
		require.NoError(t, err)
		assert.Equal(t, uint64(4), result.Count)
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		// Filtering by rotation needs a passphrase, but listing doesn't
		none, err := credential.New(ctx, v1.PoolConn, credential.WithSchema(schemaName))
		require.NoError(t, err)

		_, err = list(none, types.Ptr(true))
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)

		result, err := list(none, nil)
		require.NoError(t, err)
		assert.Equal(t, uint64(4), result.Count)
	})
}
