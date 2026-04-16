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

package main

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/pkg/cert"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestNormalizeRootPEM(t *testing.T) {
	t.Run("DecryptsEncryptedRSAPrivateKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		bundle, passphrase := encryptedRootPEM(t)
		normalized, err := normalizeRootPEM(bundle, passphrase)
		require.NoError(err)

		_, err = tls.X509KeyPair(normalized, normalized)
		assert.NoError(err)
	})

	t.Run("RejectsEncryptedKeyWithoutPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		bundle, _ := encryptedRootPEM(t)

		_, err := normalizeRootPEM(bundle, "")
		assert.EqualError(err, "certificate passphrase is required for encrypted private key")
	})

	t.Run("RejectsUnsupportedEncryptedPKCS8", func(t *testing.T) {
		assert := assert.New(t)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("cert")})
		keyPEM := pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte("key")})

		_, err := normalizeRootPEM(append(certPEM, keyPEM...), "secret")
		assert.EqualError(err, "encrypted PKCS#8 private keys are not supported")
	})
}

func TestStoragePassphraseOpts(t *testing.T) {
	t.Run("OptionalForRun", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		cmd := &ServerCommand{}
		opts, err := cmd.storagePassphraseOpts(false)
		require.NoError(err)
		assert.Nil(opts)
	})

	t.Run("RequiredForBootstrap", func(t *testing.T) {
		assert := assert.New(t)

		cmd := &ServerCommand{}
		_, err := cmd.storagePassphraseOpts(true)
		assert.EqualError(err, "at least one storage passphrase is required")
	})

	t.Run("BuildsSequentialVersions", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		cmd := &ServerCommand{StoragePassphrase: []string{"test12345", "test67890"}}
		opts, err := cmd.storagePassphraseOpts(true)
		require.NoError(err)
		require.Len(opts, 2)
		assert.NotNil(opts[0])
		assert.NotNil(opts[1])
	})
}

func encryptedRootPEM(t *testing.T) ([]byte, string) {
	t.Helper()

	root, err := cert.New(
		cert.WithCommonName("Example Root CA"),
		cert.WithOrganization("Example Org", ""),
		cert.WithExpiry(24*time.Hour),
		cert.WithRSAKey(2048),
		cert.WithRoot(),
	)
	require.NoError(t, err)

	rsaKey, ok := root.PrivateKey().(*rsa.PrivateKey)
	require.True(t, ok)

	der := x509.MarshalPKCS1PrivateKey(rsaKey)
	passphrase := "bundle-secret"
	block, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", der, []byte(passphrase), x509.PEMCipherAES256)
	require.NoError(t, err)

	var bundle bytes.Buffer
	require.NoError(t, root.Write(&bundle))
	require.NoError(t, pem.Encode(&bundle, block))

	return bundle.Bytes(), passphrase
}
