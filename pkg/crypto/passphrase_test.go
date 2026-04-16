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

package crypto_test

import (
	"testing"

	authcrypto "github.com/mutablelogic/go-auth/pkg/crypto"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestPassphraseStore(t *testing.T) {
	t.Run("SetAndGet", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NotNil(store)
		require.NoError(store.Set(1, "root-secret"))

		passphrase, version := store.Get(1)
		assert.Equal("root-secret", passphrase)
		assert.Equal(uint64(1), version)
		assert.Equal([]uint64{1}, store.Keys())
	})

	t.Run("GetZeroReturnsLatest", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(1, "pass-one"))
		require.NoError(store.Set(7, "pass-seven"))
		require.NoError(store.Set(3, "pass-three"))

		passphrase, version := store.Get(0)
		assert.Equal("pass-seven", passphrase)
		assert.Equal(uint64(7), version)
	})

	t.Run("RejectEmptyPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		err := store.Set(7, "")

		require.Error(err)
		assert.EqualError(err, "passphrase must not be empty")

		passphrase, version := store.Get(7)
		assert.Empty(passphrase)
		assert.Zero(version)
		passphrase, version = store.Get(0)
		assert.Empty(passphrase)
		assert.Zero(version)
		assert.Empty(store.Keys())
	})

	t.Run("RejectZeroVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		err := store.Set(0, "latest")

		require.Error(err)
		assert.EqualError(err, "passphrase version must be greater than zero")
		assert.Empty(store.Keys())
	})

	t.Run("RejectDuplicateVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(4, "pass-first"))

		err := store.Set(4, "pass-second")
		require.Error(err)
		assert.EqualError(err, "passphrase version already exists")

		passphrase, version := store.Get(4)
		assert.Equal("pass-first", passphrase)
		assert.Equal(uint64(4), version)
		assert.Equal([]uint64{4}, store.Keys())
	})

	t.Run("Keys", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(2, "pass-two"))
		require.NoError(store.Set(1, "pass-one"))
		require.NoError(store.Set(9, "pass-nine"))

		passphrase, version := store.Get(2)
		assert.Equal("pass-two", passphrase)
		assert.Equal(uint64(2), version)
		assert.Equal([]uint64{1, 2, 9}, store.Keys())
	})

	t.Run("RejectWhitespaceOnlyPassphrase", func(t *testing.T) {
		assert := assert.New(t)

		store := authcrypto.NewPassphrases()
		err := store.Set(8, "   \t\n")

		assert.EqualError(err, "passphrase must not be empty")
	})

	t.Run("RejectShortPassphrase", func(t *testing.T) {
		assert := assert.New(t)

		store := authcrypto.NewPassphrases()
		err := store.Set(8, "short")

		assert.EqualError(err, "passphrase must be at least 8 characters")
	})
}

func TestPassphrasesEncryptDecrypt(t *testing.T) {
	t.Run("EncryptDecryptString", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(4, "secret-passphrase"))

		version, ciphertext, err := store.EncryptString(4, "private-key-material")
		require.NoError(err)
		assert.Equal(uint64(4), version)
		assert.NotEmpty(ciphertext)

		plaintext, err := store.DecryptString(4, ciphertext)
		require.NoError(err)
		assert.Equal("private-key-material", plaintext)
	})

	t.Run("EncryptUsesLatestVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(2, "two-passphrase"))
		require.NoError(store.Set(8, "eight-passphrase"))

		version, ciphertext, err := store.Encrypt(0, []byte("secret-bytes"))
		require.NoError(err)
		assert.Equal(uint64(8), version)
		assert.NotEmpty(ciphertext)

		plaintext, err := store.Decrypt(8, ciphertext)
		require.NoError(err)
		assert.Equal([]byte("secret-bytes"), plaintext)
	})

	t.Run("EncryptMissingVersion", func(t *testing.T) {
		assert := assert.New(t)

		store := authcrypto.NewPassphrases()
		version, ciphertext, err := store.EncryptString(1, "secret")

		assert.EqualError(err, "passphrase version not found")
		assert.Zero(version)
		assert.Empty(ciphertext)
	})

	t.Run("DecryptMissingVersion", func(t *testing.T) {
		assert := assert.New(t)

		store := authcrypto.NewPassphrases()
		plaintext, err := store.DecryptString(1, "Zm9v")

		assert.EqualError(err, "passphrase version not found")
		assert.Empty(plaintext)
	})
}

func BenchmarkDeriveKey(b *testing.B) {
	salt, err := authcrypto.GenerateSalt()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		authcrypto.DeriveKey("test-passphrase", salt)
	}
}
