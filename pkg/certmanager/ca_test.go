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
	"context"
	"crypto/rsa"
	"crypto/x509"
	"testing"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/certmanager"
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	schema "github.com/djthorpe/go-auth/schema/cert"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestCA_001(t *testing.T) {
	t.Run("CreateCADefaultsToRootSubjectAndCapsExpiry", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, rootCert, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_default",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "example_ca"})
		require.NoError(err)
		require.NotNil(caRow)

		assert.Equal("example_ca", caRow.Name)
		assert.True(caRow.IsCA)
		assert.False(caRow.IsRoot())
		assert.True(types.Value(caRow.Enabled))
		assert.Empty(caRow.Tags)
		assert.Empty(caRow.EffectiveTags)
		require.NotNil(caRow.Signer)
		assert.Equal(schema.RootCertName, *caRow.Signer)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))
		assert.Equal(rootRow.Subject, caRow.Subject)

		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)
		assert.Equal("example_ca", parsedCA.Subject.CommonName)
		assert.Equal(rootCert.Subject.Organization, parsedCA.Subject.Organization)
		assert.Equal(rootCert.Subject.String(), parsedCA.Issuer.String())
		assert.False(parsedCA.NotAfter.After(rootCert.NotAfter))
		assert.True(parsedCA.NotAfter.After(parsedCA.NotBefore))
		assert.LessOrEqual(parsedCA.NotAfter.Sub(parsedCA.NotBefore), 24*time.Hour)
		assert.Equal(uint64(1), caRow.PV)
	})

	t.Run("CreateCAUsesExplicitSubjectAndExpiry", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, rootCert, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_custom",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		subject := schema.SubjectMeta{
			Org:           types.Ptr("Example Org"),
			Unit:          types.Ptr("Security"),
			Country:       types.Ptr("US"),
			State:         types.Ptr("California"),
			City:          types.Ptr("San Francisco"),
			StreetAddress: types.Ptr("1 Example Way"),
			PostalCode:    types.Ptr("94105"),
		}

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:    "custom_ca",
			Expiry:  2 * time.Hour,
			Subject: &subject,
			Tags:    []string{"child-tag", " child-extra "},
		})
		require.NoError(err)
		require.NotNil(caRow)

		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)
		assert.Equal("custom_ca", parsedCA.Subject.CommonName)
		assert.Equal(rootCert.Subject.String(), parsedCA.Issuer.String())
		assert.Equal(2*time.Hour, parsedCA.NotAfter.Sub(parsedCA.NotBefore))
		assert.True(types.Value(caRow.Enabled))
		assert.Equal([]string{"child-tag", "child-extra"}, caRow.Tags)
		assert.Equal([]string{"child-extra", "child-tag"}, caRow.EffectiveTags)
		assert.Equal(uint64(1), caRow.PV)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(*caRow.Subject)))
		assert.Equal("Example Org", types.Value(storedSubject.Org))
		assert.Equal("Security", types.Value(storedSubject.Unit))
		assert.Equal("US", types.Value(storedSubject.Country))
		assert.Equal("California", types.Value(storedSubject.State))
		assert.Equal("San Francisco", types.Value(storedSubject.City))
		assert.Equal("1 Example Way", types.Value(storedSubject.StreetAddress))
		assert.Equal("94105", types.Value(storedSubject.PostalCode))
	})

	t.Run("CreateCAIncludesParentTagsInEffectiveTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_effective_tags",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_ca_effective_tags.cert SET tags = ARRAY['root-tag'] WHERE name = '$root$'`))

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:   "tagged_ca",
			Expiry: time.Hour,
			Tags:   []string{"child-tag", "root-tag"},
		})
		require.NoError(err)
		require.NotNil(caRow)

		assert.Equal([]string{"child-tag", "root-tag"}, caRow.Tags)
		assert.Equal([]string{"child-tag", "root-tag"}, caRow.EffectiveTags)
	})

	t.Run("CreateCAEncryptsPrivateKeyWithLatestPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_encrypted_key",
			manager.WithPassphrase(2, "root-secret-2"),
			manager.WithPassphrase(9, "root-secret-9"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "encrypted_ca", Expiry: time.Hour})
		require.NoError(err)
		require.NotNil(caRow)

		assert.Equal(uint64(9), caRow.PV)
		assert.Empty(caRow.Key)
		assert.True(types.Value(caRow.Enabled))

		var storedCA schema.Cert
		require.NoError(m.Get(context.Background(), &storedCA, schema.CertName("encrypted_ca")))
		assert.Equal(uint64(9), storedCA.PV)
		assert.NotEmpty(storedCA.Key)

		store := authcrypto.NewPassphrases()
		require.NoError(store.Set(2, "root-secret-2"))
		require.NoError(store.Set(9, "root-secret-9"))

		decryptedKey, err := store.Decrypt(storedCA.PV, string(storedCA.Key))
		require.NoError(err)

		parsedKeyAny, err := x509.ParsePKCS8PrivateKey(decryptedKey)
		require.NoError(err)
		_, ok := parsedKeyAny.(*rsa.PrivateKey)
		assert.True(ok)
	})

	t.Run("CreateCARejectsDuplicateName", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_duplicate",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		_, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "duplicate_ca", Expiry: time.Hour})
		require.NoError(err)

		_, err = m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "duplicate_ca", Expiry: time.Hour})
		require.Error(err)
		assert.ErrorIs(err, httpresponse.ErrConflict)
	})
}
