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
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	test "github.com/mutablelogic/go-auth/credential/pg/test"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestDeleteCredential(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)

	remove := func(key string) (*schema.Credential, error) {
		return manager.DeleteCredential(ctx, schema.CredentialKey{Key: key})
	}

	t.Run("Existing", func(t *testing.T) {
		mustCreate(t, ctx, manager, "del_existing", "token-to-delete")
		deleted, err := remove("del_existing")
		require.NoError(t, err)
		require.NotNil(t, deleted)
		assert.Equal(t, "del_existing", deleted.Key)
		assert.False(t, deleted.UpdatedAt.IsZero())

		// The credential is gone
		_, err = manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: "del_existing"})
		assert.ErrorIs(t, err, pg.ErrNotFound)
	})

	t.Run("Gone", func(t *testing.T) {
		// A second delete reports not found
		mustCreate(t, ctx, manager, "del_gone", "token")
		_, err := remove("del_gone")
		require.NoError(t, err)
		_, err = remove("del_gone")
		assert.ErrorIs(t, err, pg.ErrNotFound)
		assert.ErrorIs(t, auth.HTTPError(err), httpresponse.ErrNotFound)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := remove("del_missing")
		assert.ErrorIs(t, err, pg.ErrNotFound)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		_, err := remove("bad-key!")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("OtherCredentials", func(t *testing.T) {
		// Deleting a credential leaves the others
		mustCreate(t, ctx, manager, "del_keep", "keep")
		mustCreate(t, ctx, manager, "del_remove", "remove")
		_, err := remove("del_remove")
		require.NoError(t, err)
		_, err = manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: "del_keep"})
		assert.NoError(t, err)
	})
}
