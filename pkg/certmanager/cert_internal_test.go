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

package manager

import (
	"context"
	"math/big"
	"testing"
	"time"

	auth "github.com/djthorpe/go-auth"
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	schema "github.com/djthorpe/go-auth/schema/cert"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func Test_capExpiry_001(t *testing.T) {
	t.Run("RejectsFutureCA", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		now := time.Now().Truncate(time.Second)
		expires, err := capExpiry(schema.DefaultCertExpiry, schema.DefaultCertExpiry, "certificate authority", now.Add(time.Minute), now.Add(2*time.Hour))
		require.Error(err)
		assert.Zero(expires)
		assert.EqualError(err, "certificate authority is not valid yet")
	})

	t.Run("RejectsExpiredCA", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		now := time.Now().Truncate(time.Second)
		expires, err := capExpiry(schema.DefaultCertExpiry, schema.DefaultCertExpiry, "certificate authority", now.Add(-2*time.Hour), now.Add(-time.Second))
		require.Error(err)
		assert.Zero(expires)
		assert.EqualError(err, "certificate authority has expired")
	})

	t.Run("RejectsFutureRoot", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		now := time.Now().Truncate(time.Second)
		expires, err := capExpiry(schema.DefaultCACertExpiry, schema.DefaultCACertExpiry, "root certificate", now.Add(time.Minute), now.Add(2*time.Hour))
		require.Error(err)
		assert.Zero(expires)
		assert.EqualError(err, "root certificate is not valid yet")
	})

	t.Run("RejectsExpiredRoot", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		now := time.Now().Truncate(time.Second)
		expires, err := capExpiry(schema.DefaultCACertExpiry, schema.DefaultCACertExpiry, "root certificate", now.Add(-2*time.Hour), now.Add(-time.Second))
		require.Error(err)
		assert.Zero(expires)
		assert.EqualError(err, "root certificate has expired")
	})
}

func Test_nextSerial_001(t *testing.T) {
	t.Run("IncrementsValidSerial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		next, err := nextSerial("41")
		require.NoError(err)
		assert.Equal(big.NewInt(42), next)
	})

	t.Run("RejectsInvalidSerial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		next, err := nextSerial("abc")
		require.Error(err)
		assert.Nil(next)
		assert.EqualError(err, "Bad Request: serial is invalid")
	})

	t.Run("RejectsNegativeSerial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		next, err := nextSerial("-1")
		require.Error(err)
		assert.Nil(next)
		assert.EqualError(err, "Bad Request: serial is invalid")
	})
}

func Test_certChainSelector_001(t *testing.T) {
	t.Run("RejectsUnsupportedOperation", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		query, err := certChainSelector(schema.CertKey{Name: "leaf", Serial: "1"}).Select(pg.NewBind(), pg.Get)
		require.Error(err)
		assert.Empty(query)
		assert.EqualError(err, `Bad Request: certChainSelector: operation "GET" is not supported`)
	})
}

func Test_rootHelpers_001(t *testing.T) {
	t.Run("SerialTextReturnsEmptyForNil", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("", serialText(nil))
		assert.Equal("42", serialText(big.NewInt(42)))
	})

	t.Run("RootCertRowRejectsNilCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		row, err := rootCertRow(1, nil, nil)
		require.Error(err)
		assert.Equal(schema.CertWithPrivateKey{}, row)
		assert.EqualError(err, "root certificate is required")
	})

	t.Run("StoredCertSignerRejectsUnknownPassphraseVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := &Manager{opt: opt{passphrase: authcrypto.NewPassphrases()}}
		_, _, err := m.storedCertSigner(schema.CertWithPrivateKey{
			Cert: schema.Cert{Cert: []byte("not-a-cert")},
			PV:   99,
			Key:  []byte("ciphertext"),
		})
		require.Error(err)
		assert.ErrorIs(err, auth.ErrServiceUnavailable)
		assert.EqualError(err, "service unavailable: stored certificate private keys require a configured --storage-passphrase version on server")
	})

	t.Run("StoredCertSignerRejectsInvalidCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(1, "root-secret-1"))
		version, ciphertext, err := store.Encrypt(1, []byte("not-a-private-key"))
		require.NoError(err)

		m := &Manager{opt: opt{passphrase: store}}
		_, _, err = m.storedCertSigner(schema.CertWithPrivateKey{
			Cert: schema.Cert{Cert: []byte("not-a-cert")},
			PV:   version,
			Key:  []byte(ciphertext),
		})
		require.Error(err)
		assert.Contains(err.Error(), "certificate")
	})

	t.Run("StoredCertSignerRejectsWrongPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		encryptStore := authcrypto.NewPassphrases()
		require.NoError(encryptStore.Set(1, "root-secret-1"))
		version, ciphertext, err := encryptStore.Encrypt(1, []byte("not-a-private-key"))
		require.NoError(err)

		decryptStore := authcrypto.NewPassphrases()
		require.NoError(decryptStore.Set(1, "root-secret-2"))

		m := &Manager{opt: opt{passphrase: decryptStore}}
		_, _, err = m.storedCertSigner(schema.CertWithPrivateKey{
			Cert: schema.Cert{Cert: []byte("not-a-cert")},
			PV:   version,
			Key:  []byte(ciphertext),
		})
		require.Error(err)
		assert.ErrorIs(err, auth.ErrConflict)
		assert.EqualError(err, "conflict: stored certificate private keys cannot be decrypted with current --storage-passphrase")
	})
}

func Test_certificateStoragePassphrase_001(t *testing.T) {
	t.Run("CreateCARequiresStoragePassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result, err := (&Manager{}).CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca"})
		require.Error(err)
		assert.Nil(result)
		assert.ErrorIs(err, auth.ErrServiceUnavailable)
		assert.EqualError(err, "service unavailable: creating certificates requires --storage-passphrase on server")
	})

	t.Run("CreateCertRequiresStoragePassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		result, err := (&Manager{}).CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert"}, schema.CertKey{Name: "issuer_ca", Serial: "1"})
		require.Error(err)
		assert.Nil(result)
		assert.ErrorIs(err, auth.ErrServiceUnavailable)
		assert.EqualError(err, "service unavailable: creating certificates requires --storage-passphrase on server")
	})
}
