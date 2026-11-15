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
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type s3Credentials struct {
	AccessKeyID     string `json:"access_key_id"`
	SecretAccessKey string `json:"secret_access_key"`
	Region          string `json:"region"`
}

///////////////////////////////////////////////////////////////////////////////
// HELPERS

// stored returns the passphrase version and encrypted credentials stored for
// the key
func stored(t *testing.T, ctx context.Context, manager *credential.Manager, key string) (uint64, []byte) {
	t.Helper()
	var row schema.CredentialGet
	require.NoError(t, manager.Get(ctx, &row, schema.CredentialKey{Key: key}))
	data, ok := row.Credentials.([]byte)
	require.True(t, ok, "credentials are %T, not []byte", row.Credentials)
	return row.PV, data
}

// decrypt decrypts the credentials stored for the key into out
func decrypt(t *testing.T, ctx context.Context, manager *credential.Manager, key string, out any) {
	t.Helper()
	data, err := manager.GetCredentialWithoutPassphrase(ctx, schema.CredentialKey{Key: key})
	require.NoError(t, err)
	require.NoError(t, json.Unmarshal(data, out))
}

///////////////////////////////////////////////////////////////////////////////
// TESTS

func TestCreateCredential(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)

	create := func(key string, credentials any) (*schema.Credential, error) {
		return manager.CreateCredential(ctx, schema.CredentialCreate{
			CredentialKey: schema.CredentialKey{Key: key},
			Credentials:   credentials,
		})
	}

	t.Run("String", func(t *testing.T) {
		cred, err := create("create_string", "my-secret-token")
		require.NoError(t, err)
		require.NotNil(t, cred)
		assert.Equal(t, "create_string", cred.Key)
		assert.False(t, cred.UpdatedAt.IsZero())

		var value string
		decrypt(t, ctx, manager, "create_string", &value)
		assert.Equal(t, "my-secret-token", value)
	})

	t.Run("Struct", func(t *testing.T) {
		input := s3Credentials{
			AccessKeyID:     "AKIAIOSFODNN7EXAMPLE",
			SecretAccessKey: "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
			Region:          "us-east-1",
		}
		cred, err := create("create_s3", input)
		require.NoError(t, err)
		assert.Equal(t, "create_s3", cred.Key)

		var output s3Credentials
		decrypt(t, ctx, manager, "create_s3", &output)
		assert.Equal(t, input, output)
	})

	t.Run("Encrypted", func(t *testing.T) {
		// The credentials are stored encrypted, with the passphrase version
		_, err := create("create_encrypted", "plaintext-secret")
		require.NoError(t, err)
		pv, data := stored(t, ctx, manager, "create_encrypted")
		assert.Equal(t, uint64(test.PassphraseVersion), pv)
		assert.NotEmpty(t, data)
		assert.NotContains(t, string(data), "plaintext-secret")
	})

	t.Run("Upsert", func(t *testing.T) {
		// Creating a credential with an existing key replaces it
		first, err := create("create_upsert", "original-secret")
		require.NoError(t, err)
		second, err := create("create_upsert", "updated-secret")
		require.NoError(t, err)
		assert.False(t, second.UpdatedAt.Before(first.UpdatedAt))

		var value string
		decrypt(t, ctx, manager, "create_upsert", &value)
		assert.Equal(t, "updated-secret", value)
	})

	t.Run("KeyWithDash", func(t *testing.T) {
		// Keys are identifiers, which can contain "-" and "_"
		cred, err := create("create-with_dash", "secret")
		require.NoError(t, err)
		assert.Equal(t, "create-with_dash", cred.Key)
	})

	t.Run("KeyTrimmed", func(t *testing.T) {
		cred, err := create("  create_trimmed  ", "secret")
		require.NoError(t, err)
		assert.Equal(t, "create_trimmed", cred.Key)
	})

	t.Run("InvalidKey", func(t *testing.T) {
		for _, key := range []string{"", "bad-key!", "1starts_with_digit", "_starts_with_underscore", "has space"} {
			_, err := create(key, "secret")
			assert.ErrorIs(t, err, auth.ErrBadParameter, "key %q", key)
			assert.ErrorIs(t, auth.HTTPError(err), httpresponse.ErrBadRequest, "key %q", key)
		}
	})

	t.Run("EmptyCredentials", func(t *testing.T) {
		for _, credentials := range []any{nil, "", []byte{}, struct{}{}} {
			_, err := create("create_empty", credentials)
			assert.ErrorIs(t, err, auth.ErrBadParameter, "credentials %#v", credentials)
		}
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		// A manager without a passphrase can't encrypt credentials
		unencrypted, err := credential.New(ctx, manager.PoolConn, credential.WithSchema(test.Schema()))
		require.NoError(t, err)
		_, err = unencrypted.CreateCredential(ctx, schema.CredentialCreate{
			CredentialKey: schema.CredentialKey{Key: "create_no_passphrase"},
			Credentials:   "secret",
		})
		assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
		assert.ErrorIs(t, auth.HTTPError(err), httpresponse.ErrServiceUnavailable)

		// The key is checked before the credentials are encrypted, so an
		// invalid key is reported even without a passphrase
		_, err = unencrypted.CreateCredential(ctx, schema.CredentialCreate{
			CredentialKey: schema.CredentialKey{Key: "bad-key!"},
			Credentials:   "secret",
		})
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})
}
