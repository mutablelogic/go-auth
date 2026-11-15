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
	"encoding/json"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential/pg"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	test "github.com/mutablelogic/go-auth/credential/pg/test"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestRotateCredential(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)

	// Credentials encrypted with passphrase version one, rotated by a
	// manager whose latest version is two
	schemaName := test.IsolatedSchema(t)
	v1 := test.SchemaManager(t, schemaName)
	v2 := test.SchemaManager(t, schemaName, credential.WithPassphrase(2, "second passphrase"))
	rotate := func(manager *credential.Manager, key string) (*schema.Credential, error) {
		return manager.RotateCredential(ctx, schema.CredentialKey{Key: key})
	}

	t.Run("Rotate", func(t *testing.T) {
		mustCreate(t, ctx, v1, "rotate_upgrade", map[string]string{"token": "rotate-me"})
		pv, _ := stored(t, ctx, v1, "rotate_upgrade")
		require.Equal(t, uint64(test.PassphraseVersion), pv)

		cred, err := rotate(v2, "rotate_upgrade")
		require.NoError(t, err)
		assert.Equal(t, "rotate_upgrade", cred.Key)

		// The credential uses version two, and its value is unchanged
		pv, _ = stored(t, ctx, v2, "rotate_upgrade")
		assert.Equal(t, uint64(2), pv)
		got, err := v2.GetCredential(ctx, schema.CredentialKey{Key: "rotate_upgrade"}, "second passphrase")
		require.NoError(t, err)
		assert.JSONEq(t, `{"token":"rotate-me"}`, string(got))

		// The old passphrase no longer reads it
		_, err = v2.GetCredential(ctx, schema.CredentialKey{Key: "rotate_upgrade"}, test.Passphrase)
		assert.ErrorIs(t, err, auth.ErrForbidden)
	})

	t.Run("NotModified", func(t *testing.T) {
		// A credential which already uses the latest version is unchanged
		mustCreate(t, ctx, v2, "rotate_noop", "unchanged-secret")
		_, err := rotate(v2, "rotate_noop")
		assert.ErrorIs(t, err, auth.ErrNotModified)
		assert.ErrorIs(t, auth.HTTPError(err), httpresponse.Err(304))
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := rotate(v2, "rotate_missing")
		assert.ErrorIs(t, err, pg.ErrNotFound)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		_, err := rotate(v2, "bad-key!")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		mustCreate(t, ctx, v1, "rotate_no_passphrase", "secret")
		none, err := credential.New(ctx, v1.PoolConn, credential.WithSchema(schemaName))
		require.NoError(t, err)
		_, err = rotate(none, "rotate_no_passphrase")
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
	})

	t.Run("PassphraseRetired", func(t *testing.T) {
		// Without the credential's passphrase version, it can't be decrypted
		// to rotate it
		mustCreate(t, ctx, v1, "rotate_retired", "secret")
		retired, err := credential.New(ctx, v1.PoolConn, credential.WithSchema(schemaName), credential.WithPassphrase(3, "third passphrase"))
		require.NoError(t, err)
		_, err = rotate(retired, "rotate_retired")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("RotateList", func(t *testing.T) {
		// After rotating, a credential no longer needs rotating
		mustCreate(t, ctx, v1, "rotate_listed", "secret")
		needs := func() bool {
			list, err := v2.ListCredentials(ctx, schema.CredentialListRequest{Rotate: types.Ptr(true)})
			require.NoError(t, err)
			for _, cred := range list.Body {
				if cred.Key == "rotate_listed" {
					return true
				}
			}
			return false
		}
		assert.True(t, needs())
		_, err := rotate(v2, "rotate_listed")
		require.NoError(t, err)
		assert.False(t, needs())
	})
}

func TestRotateCredentialConflict(t *testing.T) {
	// The update which rotates a credential only replaces the encrypted data
	// it read, so a credential changed or deleted in the meantime is left
	// alone
	_, ctx := test.Begin(t)
	defer test.End(t)
	manager := test.IsolatedManager(t)

	replace := func(key string, oldPV uint64, oldCredentials []byte) error {
		var result schema.Credential
		return manager.Insert(ctx, &result, schema.CredentialRotate{
			CredentialKey:  schema.CredentialKey{Key: key},
			PV:             2,
			Credentials:    []byte("new ciphertext"),
			OldPV:          oldPV,
			OldCredentials: oldCredentials,
		})
	}

	t.Run("Changed", func(t *testing.T) {
		// The credential was replaced after it was read
		mustCreate(t, ctx, manager, "conflict_changed", "first")
		pv, read := stored(t, ctx, manager, "conflict_changed")
		mustCreate(t, ctx, manager, "conflict_changed", "second")

		assert.ErrorIs(t, pg.NormalizeError(replace("conflict_changed", pv, read)), pg.ErrNotFound)

		// The new value is still there
		data, err := manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: "conflict_changed"})
		require.NoError(t, err)
		var value string
		require.NoError(t, json.Unmarshal(data, &value))
		assert.Equal(t, "second", value)
	})

	t.Run("Deleted", func(t *testing.T) {
		// The credential was deleted after it was read, and isn't recreated
		mustCreate(t, ctx, manager, "conflict_deleted", "secret")
		pv, read := stored(t, ctx, manager, "conflict_deleted")
		_, err := manager.DeleteCredential(ctx, schema.CredentialKey{Key: "conflict_deleted"})
		require.NoError(t, err)

		assert.ErrorIs(t, pg.NormalizeError(replace("conflict_deleted", pv, read)), pg.ErrNotFound)
		_, err = manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: "conflict_deleted"})
		assert.ErrorIs(t, err, pg.ErrNotFound)
	})

	t.Run("Unchanged", func(t *testing.T) {
		// The credential is replaced when it is unchanged
		mustCreate(t, ctx, manager, "conflict_unchanged", "secret")
		pv, read := stored(t, ctx, manager, "conflict_unchanged")
		require.NoError(t, replace("conflict_unchanged", pv, read))
		pv, data := stored(t, ctx, manager, "conflict_unchanged")
		assert.Equal(t, uint64(2), pv)
		assert.Equal(t, "new ciphertext", string(data))
	})
}
