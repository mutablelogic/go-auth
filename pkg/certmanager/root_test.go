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
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	// Packages
	cert "github.com/djthorpe/go-auth/pkg/cert"
	manager "github.com/djthorpe/go-auth/pkg/certmanager"
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	schema "github.com/djthorpe/go-auth/schema/cert"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestRoot_001(t *testing.T) {
	t.Run("InsertRootCert", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t, manager.WithPassphrase(1, "root-secret-1"))
		sourceRoot, parsedCert, key, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")

		root, err := m.InsertRootCert(context.Background(), pemValue)
		require.NoError(err)
		require.NotNil(root)

		assert.Equal(schema.RootCertName, root.Name)
		assert.True(root.IsCA)
		assert.True(root.IsRoot())
		assert.Nil(root.Signer)
		require.NotNil(root.Subject)
		assert.NotZero(*root.Subject)
		assert.NotEmpty(root.Cert)
		assert.NotEmpty(root.Key)
		assert.True(types.Value(root.Enabled))
		assert.Empty(root.Tags)
		assert.Empty(root.EffectiveTags)
		assert.Equal(uint64(1), root.PV)

		storedCert, err := x509.ParseCertificate(root.Cert)
		require.NoError(err)
		assert.True(storedCert.IsCA)
		assert.Equal(parsedCert.Subject.String(), storedCert.Subject.String())
		assert.Equal(parsedCert.Issuer.String(), storedCert.Issuer.String())

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(1, "root-secret-1"))
		decryptedKey, err := store.Decrypt(root.PV, string(root.Key))
		require.NoError(err)

		parsedKeyAny, err := x509.ParsePKCS8PrivateKey(decryptedKey)
		require.NoError(err)
		parsedKey, ok := parsedKeyAny.(*rsa.PrivateKey)
		require.True(ok)
		assert.Equal(key.PublicKey.N, parsedKey.PublicKey.N)
		assert.Equal(key.PublicKey.E, parsedKey.PublicKey.E)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(*root.Subject)))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().Org), types.Value(storedSubject.Org))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().Unit), types.Value(storedSubject.Unit))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().Country), types.Value(storedSubject.Country))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().State), types.Value(storedSubject.State))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().City), types.Value(storedSubject.City))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().StreetAddress), types.Value(storedSubject.StreetAddress))
		assert.Equal(types.Value(sourceRoot.SubjectMeta().PostalCode), types.Value(storedSubject.PostalCode))
	})

	t.Run("InsertRootCertEncryptsPrivateKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t,
			manager.WithPassphrase(2, "root-secret-2"),
			manager.WithPassphrase(9, "root-secret-9"),
		)
		_, _, key, pemValue := newRootPEMBundle(t, "Encrypted Root CA", "Example Org")
		root, err := m.InsertRootCert(context.Background(), pemValue)
		require.NoError(err)
		require.NotNil(root)

		assert.Equal(uint64(9), root.PV)
		assert.NotEmpty(root.Key)
		assert.True(types.Value(root.Enabled))

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(2, "root-secret-2"))
		require.NoError(store.Set(9, "root-secret-9"))

		decryptedKey, err := store.Decrypt(root.PV, string(root.Key))
		require.NoError(err)

		parsedKeyAny, err := x509.ParsePKCS8PrivateKey(decryptedKey)
		require.NoError(err)
		parsedKey, ok := parsedKeyAny.(*rsa.PrivateKey)
		require.True(ok)
		assert.Equal(key.PublicKey.N, parsedKey.PublicKey.N)
		assert.Equal(key.PublicKey.E, parsedKey.PublicKey.E)
	})

	t.Run("InsertRootCertRejectsMissingPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManager(t)
		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")

		_, err := m.InsertRootCert(context.Background(), pemValue)
		require.Error(err)
		assert.EqualError(err, "root certificate storage passphrase is required")
	})

	t.Run("InsertRootCertRejectsDuplicate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t, manager.WithPassphrase(1, "root-secret-1"))
		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		_, err := m.InsertRootCert(context.Background(), pemValue)
		require.NoError(err)

		_, _, _, pemValue2 := newRootPEMBundle(t, "Second Root CA", "Example Org")
		_, err = m.InsertRootCert(context.Background(), pemValue2)
		require.Error(err)
		assert.ErrorIs(err, httpresponse.ErrConflict)
	})

	t.Run("InsertRootCertRejectsInvalidInput", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newTestManagerWithOpts(t, manager.WithPassphrase(1, "root-secret-1"))

		_, err := m.InsertRootCert(context.Background(), "")
		require.Error(err)
		assert.EqualError(err, "missing certificate or key")

		_, err = m.InsertRootCert(context.Background(), "not a pem")
		require.Error(err)
		assert.EqualError(err, "invalid PEM block")
	})
}

func newRootPEMBundle(t *testing.T, commonName, organization string) (*cert.Cert, *x509.Certificate, *rsa.PrivateKey, string) {
	t.Helper()

	root, err := cert.New(
		cert.WithCommonName(commonName),
		cert.WithOrganization(organization, ""),
		cert.WithExpiry(24*time.Hour),
		cert.WithRSAKey(2048),
		cert.WithRoot(),
	)
	require.NoError(t, err)

	parsed, err := x509.ParseCertificate(root.CertMeta().Cert)
	require.NoError(t, err)

	key, ok := root.PrivateKey().(*rsa.PrivateKey)
	require.True(t, ok)

	var pemValue bytes.Buffer
	require.NoError(t, root.Write(&pemValue))
	require.NoError(t, root.WritePrivateKey(&pemValue))

	return root, parsed, key, pemValue.String()
}
