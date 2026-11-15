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
	"context"
	"encoding/json"
	"testing"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	credential "github.com/mutablelogic/go-auth/credential/pg"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	test "github.com/mutablelogic/go-auth/credential/pg/test"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type googleCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	RefreshToken string `json:"refresh_token"`
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS

// mustCreate stores the credentials under the key
func mustCreate(t *testing.T, ctx context.Context, manager *credential.Manager, key string, credentials any) {
	t.Helper()
	_, err := manager.CreateCredential(ctx, schema.CredentialCreate{
		CredentialKey: schema.CredentialKey{Key: key},
		Credentials:   credentials,
	})
	require.NoError(t, err)
}

// newManager returns a manager on the shared schema with the passphrases,
// which are numbered from version one
func newManager(t *testing.T, ctx context.Context, shared *credential.Manager, passphrases map[uint64]string) *credential.Manager {
	t.Helper()
	opts := []credential.Opt{credential.WithSchema(test.Schema())}
	for version, passphrase := range passphrases {
		opts = append(opts, credential.WithPassphrase(version, passphrase))
	}
	manager, err := credential.New(ctx, shared.PoolConn, opts...)
	require.NoError(t, err)
	return manager
}

///////////////////////////////////////////////////////////////////////////////
// TESTS - GetCredential (requires passphrase)

func TestGetCredential(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)

	get := func(key, passphrase string) (json.RawMessage, error) {
		return manager.GetCredential(ctx, schema.CredentialKey{Key: key}, passphrase)
	}

	t.Run("String", func(t *testing.T) {
		mustCreate(t, ctx, manager, "get_string", "my-api-key")
		got, err := get("get_string", test.Passphrase)
		require.NoError(t, err)

		var value string
		require.NoError(t, json.Unmarshal(got, &value))
		assert.Equal(t, "my-api-key", value)
	})

	t.Run("Struct", func(t *testing.T) {
		input := googleCredentials{
			ClientID:     "client-id-123",
			ClientSecret: "client-secret-456",
			RefreshToken: "1//refresh-token-789",
		}
		mustCreate(t, ctx, manager, "get_google", input)
		got, err := get("get_google", test.Passphrase)
		require.NoError(t, err)

		var output googleCredentials
		require.NoError(t, json.Unmarshal(got, &output))
		assert.Equal(t, input, output)
	})

	t.Run("WrongPassphrase", func(t *testing.T) {
		mustCreate(t, ctx, manager, "get_wrong_pass", "secret")
		for _, passphrase := range []string{"wrong-passphrase", "", test.Passphrase + " "} {
			_, err := get("get_wrong_pass", passphrase)
			assert.ErrorIs(t, err, auth.ErrForbidden, "passphrase %q", passphrase)
			assert.ErrorIs(t, auth.HTTPError(err), httpresponse.ErrForbidden, "passphrase %q", passphrase)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := get("get_never_created", test.Passphrase)
		assert.ErrorIs(t, err, pg.ErrNotFound)
		assert.ErrorIs(t, auth.HTTPError(err), httpresponse.ErrNotFound)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		_, err := get("bad-key!", test.Passphrase)
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("PassphraseVersion", func(t *testing.T) {
		// A credential is read with the passphrase of the version it was
		// encrypted with, which is not the latest once another is added
		mustCreate(t, ctx, manager, "get_version", "secret")
		both := newManager(t, ctx, manager, map[uint64]string{test.PassphraseVersion: test.Passphrase, 2: "second passphrase"})

		got, err := both.GetCredential(ctx, schema.CredentialKey{Key: "get_version"}, test.Passphrase)
		require.NoError(t, err)
		assert.JSONEq(t, `"secret"`, string(got))

		_, err = both.GetCredential(ctx, schema.CredentialKey{Key: "get_version"}, "second passphrase")
		assert.ErrorIs(t, err, auth.ErrForbidden)
	})

	t.Run("PassphraseRetired", func(t *testing.T) {
		// A credential can't be read once its passphrase version is removed,
		// even with its passphrase
		mustCreate(t, ctx, manager, "get_retired", "secret")
		retired := newManager(t, ctx, manager, map[uint64]string{2: "second passphrase"})

		_, err := retired.GetCredential(ctx, schema.CredentialKey{Key: "get_retired"}, test.Passphrase)
		assert.ErrorIs(t, err, auth.ErrForbidden)
		_, err = retired.GetCredential(ctx, schema.CredentialKey{Key: "get_retired"}, "second passphrase")
		assert.ErrorIs(t, err, auth.ErrForbidden)
	})
}

///////////////////////////////////////////////////////////////////////////////
// TESTS - GetCredentialWithoutPassphrase (internal)

func TestGetCredentialWithoutPassphrase(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)

	get := func(key string) (json.RawMessage, error) {
		return manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: key})
	}

	t.Run("String", func(t *testing.T) {
		mustCreate(t, ctx, manager, "get_internal_string", "internal-secret")
		got, err := get("get_internal_string")
		require.NoError(t, err)

		var value string
		require.NoError(t, json.Unmarshal(got, &value))
		assert.Equal(t, "internal-secret", value)
	})

	t.Run("Struct", func(t *testing.T) {
		input := googleCredentials{
			ClientID:     "id-abc",
			ClientSecret: "secret-xyz",
			RefreshToken: "refresh-000",
		}
		mustCreate(t, ctx, manager, "get_internal_google", input)
		got, err := get("get_internal_google")
		require.NoError(t, err)

		var output googleCredentials
		require.NoError(t, json.Unmarshal(got, &output))
		assert.Equal(t, input, output)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := get("also_never_created")
		assert.ErrorIs(t, err, pg.ErrNotFound)
	})

	t.Run("PassphraseRetired", func(t *testing.T) {
		// Without the credential's passphrase version, it can't be decrypted
		mustCreate(t, ctx, manager, "get_internal_retired", "secret")
		retired := newManager(t, ctx, manager, map[uint64]string{2: "second passphrase"})
		_, err := retired.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: "get_internal_retired"})
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})
}

func TestGetCredentialMeta(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)
	mustCreate(t, ctx, manager, "get_meta_string", "meta-secret")

	t.Run("Get", func(t *testing.T) {
		credential, err := manager.GetCredentialMeta(ctx, schema.CredentialKey{Key: "get_meta_string"})
		require.NoError(t, err)
		assert.Equal(t, "get_meta_string", credential.Key)
		assert.False(t, credential.UpdatedAt.IsZero())
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		// A manager without passphrases, which can't decrypt credentials, can
		// still get their keys
		none := newManager(t, ctx, manager, nil)
		credential, err := none.GetCredentialMeta(ctx, schema.CredentialKey{Key: "get_meta_string"})
		require.NoError(t, err)
		assert.Equal(t, "get_meta_string", credential.Key)
	})

	t.Run("TrimmedKey", func(t *testing.T) {
		credential, err := manager.GetCredentialMeta(ctx, schema.CredentialKey{Key: " get_meta_string "})
		require.NoError(t, err)
		assert.Equal(t, "get_meta_string", credential.Key)
	})

	t.Run("NotFound", func(t *testing.T) {
		_, err := manager.GetCredentialMeta(ctx, schema.CredentialKey{Key: "get_meta_never_created"})
		assert.ErrorIs(t, err, pg.ErrNotFound)
		assert.ErrorIs(t, auth.HTTPError(err), httpresponse.ErrNotFound)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		_, err := manager.GetCredentialMeta(ctx, schema.CredentialKey{Key: "1-bad"})
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})
}
