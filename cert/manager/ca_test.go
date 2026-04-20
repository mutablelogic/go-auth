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
	auth "github.com/mutablelogic/go-auth"
	cert "github.com/mutablelogic/go-auth/cert/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
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
		assert.NotEmpty(caRow.Serial)
		assert.True(caRow.IsCA)
		assert.False(caRow.IsRoot())
		assert.True(types.Value(caRow.Enabled))
		assert.Empty(caRow.Tags)
		assert.Empty(caRow.EffectiveTags)
		require.NotNil(caRow.Signer)
		assert.Equal(schema.RootCertName, caRow.Signer.Name)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))
		assert.Equal(rootRow.Serial, caRow.Signer.Serial)
		require.NotNil(rootRow.Subject)
		require.NotNil(caRow.Subject)
		assert.Equal(rootRow.Subject.ID, caRow.Subject.ID)

		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)
		assert.Equal("example_ca", parsedCA.Subject.CommonName)
		assert.Equal(rootCert.Subject.Organization, parsedCA.Subject.Organization)
		assert.Equal(rootCert.Subject.String(), parsedCA.Issuer.String())
		assert.False(parsedCA.NotAfter.After(rootCert.NotAfter))
		assert.True(parsedCA.NotAfter.After(parsedCA.NotBefore))
		assert.LessOrEqual(parsedCA.NotAfter.Sub(parsedCA.NotBefore), 24*time.Hour)
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
			Tags:    []string{"child-tag", " child-extra ", "child-tag", "child-extra"},
		})
		require.NoError(err)
		require.NotNil(caRow)

		assert.NotEmpty(caRow.Serial)
		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)
		assert.Equal("custom_ca", parsedCA.Subject.CommonName)
		assert.Equal(rootCert.Subject.String(), parsedCA.Issuer.String())
		assert.Equal(2*time.Hour, parsedCA.NotAfter.Sub(parsedCA.NotBefore))
		assert.True(types.Value(caRow.Enabled))
		assert.Equal([]string{"child-tag", "child-extra"}, caRow.Tags)
		assert.Equal([]string{"child-extra", "child-tag"}, caRow.EffectiveTags)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(caRow.Subject.ID)))
		assert.Equal("Example Org", types.Value(storedSubject.Org))
		assert.Equal("Security", types.Value(storedSubject.Unit))
		assert.Equal("US", types.Value(storedSubject.Country))
		assert.Equal("California", types.Value(storedSubject.State))
		assert.Equal("San Francisco", types.Value(storedSubject.City))
		assert.Equal("1 Example Way", types.Value(storedSubject.StreetAddress))
		assert.Equal("94105", types.Value(storedSubject.PostalCode))
	})

	t.Run("CreateCAMergesExplicitSubjectWithRootSubject", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, rootCert, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_merge_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		subject := schema.SubjectMeta{
			Unit:    types.Ptr("Security"),
			Country: types.Ptr("US"),
		}

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:    "merged_ca",
			Expiry:  time.Hour,
			Subject: &subject,
		})
		require.NoError(err)

		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)
		assert.Equal("merged_ca", parsedCA.Subject.CommonName)
		assert.Equal(rootCert.Subject.Organization, parsedCA.Subject.Organization)
		assert.Equal([]string{"Security"}, parsedCA.Subject.OrganizationalUnit)
		assert.Equal([]string{"US"}, parsedCA.Subject.Country)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(caRow.Subject.ID)))
		assert.Equal("Example Org", types.Value(storedSubject.Org))
		assert.Equal("Security", types.Value(storedSubject.Unit))
		assert.Equal("US", types.Value(storedSubject.Country))
	})

	t.Run("CreateCAAllowsExplicitlyClearingInheritedSubjectFields", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_clear_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		subject := schema.SubjectMeta{
			Org:  types.Ptr(""),
			Unit: types.Ptr("Security"),
		}

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:    "cleared_ca",
			Expiry:  time.Hour,
			Subject: &subject,
		})
		require.NoError(err)

		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)
		assert.Empty(parsedCA.Subject.Organization)
		assert.Equal([]string{"Security"}, parsedCA.Subject.OrganizationalUnit)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(caRow.Subject.ID)))
		assert.Nil(storedSubject.Org)
		assert.Equal("Security", types.Value(storedSubject.Unit))
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

		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_ca_effective_tags.cert SET tags = ARRAY['root-tag'] WHERE name = CHR(36) || 'root' || CHR(36)`))

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))
		assert.Equal([]string{"root-tag"}, rootRow.Tags)
		assert.Equal([]string{"root-tag"}, rootRow.EffectiveTags)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:   "tagged_ca",
			Expiry: time.Hour,
			Tags:   []string{"child-tag"},
		})
		require.NoError(err)
		require.NotNil(caRow)

		assert.NotEmpty(caRow.Serial)
		assert.Equal([]string{"child-tag"}, caRow.Tags)
		assert.Equal([]string{"child-tag", "root-tag"}, caRow.EffectiveTags)
	})

	t.Run("CreateCARejectsDisabledRoot", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_effective_enabled",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_ca_effective_enabled.cert SET enabled = FALSE WHERE name = CHR(36) || 'root' || CHR(36)`))

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))
		assert.False(types.Value(rootRow.Enabled))

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "disabled_parent_ca", Expiry: time.Hour})
		require.Error(err)
		assert.Nil(caRow)
		assert.ErrorIs(err, httpresponse.ErrConflict)
	})

	t.Run("CreateCARejectsMissingRootCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_missing_root",
			manager.WithPassphrase(1, "root-secret-1"),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "missing_root_ca", Expiry: time.Hour})
		require.Error(err)
		assert.Nil(caRow)
		assert.ErrorIs(err, auth.ErrServiceUnavailable)
		assert.EqualError(err, "service unavailable: root certificate has not been imported on server")
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

		assert.True(types.Value(caRow.Enabled))

		var storedCA schema.CertWithPrivateKey
		require.NoError(m.Get(context.Background(), &storedCA, schema.PrivateCertKey(caRow.CertKey)))
		assert.Equal(caRow.Serial, storedCA.Serial)
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

	t.Run("CreateCARejectsInvalidTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_invalid_tags",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:   "invalid_tag_ca",
			Expiry: time.Hour,
			Tags:   []string{"bad tag"},
		})
		require.Error(err)
		assert.Nil(caRow)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, `Bad Request: tag "bad tag" is invalid`)
	})

	t.Run("CreateCARejectsSAN", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_san",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:   "invalid_ca",
			Expiry: time.Hour,
			SAN:    []string{"*.example.test"},
		})
		require.Error(err)
		assert.Nil(caRow)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: san is only supported for leaf certificates")
	})

	t.Run("RenewCADisablesCurrentAndPreservesDefaults", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, rootCert, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "renew_ca", Expiry: 2 * time.Hour, Tags: []string{"child-tag"}})
		require.NoError(err)

		renewed, err := m.RenewCA(context.Background(), caRow.CertKey, schema.RenewCertRequest{})
		require.NoError(err)
		require.NotNil(renewed)

		assert.Equal(caRow.Name, renewed.Name)
		assert.Equal(nextSerialString(t, caRow.Serial), renewed.Serial)
		assert.Equal(caRow.Tags, renewed.Tags)
		require.NotNil(renewed.Signer)
		assert.Equal(schema.RootCertName, renewed.Signer.Name)

		parsedRenewed, err := x509.ParseCertificate(renewed.Cert)
		require.NoError(err)
		assert.Equal("renew_ca", parsedRenewed.Subject.CommonName)
		assert.Equal(rootCert.Subject.String(), parsedRenewed.Issuer.String())
		assert.Equal(caRow.NotAfter.Sub(caRow.NotBefore), renewed.NotAfter.Sub(renewed.NotBefore))

		var oldRow schema.Cert
		require.NoError(m.Get(context.Background(), &oldRow, caRow.CertKey))
		assert.False(types.Value(oldRow.Enabled))

		var newRow schema.Cert
		require.NoError(m.Get(context.Background(), &newRow, renewed.CertKey))
		assert.True(types.Value(newRow.Enabled))
		assert.Equal([]string{"child-tag"}, newRow.Tags)
		assert.Equal([]string{"child-tag"}, newRow.EffectiveTags)
	})

	t.Run("RenewCAMergesExplicitSubjectWithCurrentSubject", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_merge_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caSubject := schema.SubjectMeta{
			Org:     types.Ptr("Example Org"),
			Unit:    types.Ptr("Operations"),
			Country: types.Ptr("GB"),
		}
		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:    "renew_ca",
			Expiry:  2 * time.Hour,
			Subject: &caSubject,
		})
		require.NoError(err)

		renewSubject := schema.SubjectMeta{
			Unit: types.Ptr("Security"),
			City: types.Ptr("London"),
		}
		renewed, err := m.RenewCA(context.Background(), caRow.CertKey, schema.RenewCertRequest{
			Subject: &renewSubject,
		})
		require.NoError(err)

		parsedRenewed, err := x509.ParseCertificate(renewed.Cert)
		require.NoError(err)
		assert.Equal([]string{"Example Org"}, parsedRenewed.Subject.Organization)
		assert.Equal([]string{"Security"}, parsedRenewed.Subject.OrganizationalUnit)
		assert.Equal([]string{"GB"}, parsedRenewed.Subject.Country)
		assert.Equal([]string{"London"}, parsedRenewed.Subject.Locality)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(renewed.Subject.ID)))
		assert.Equal("Example Org", types.Value(storedSubject.Org))
		assert.Equal("Security", types.Value(storedSubject.Unit))
		assert.Equal("GB", types.Value(storedSubject.Country))
		assert.Equal("London", types.Value(storedSubject.City))
	})

	t.Run("RenewCAAllowsExplicitlyClearingInheritedSubjectFields", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_clear_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caSubject := schema.SubjectMeta{
			Org:  types.Ptr("Example Org"),
			Unit: types.Ptr("Operations"),
		}
		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:    "renew_ca",
			Expiry:  2 * time.Hour,
			Subject: &caSubject,
		})
		require.NoError(err)

		renewSubject := schema.SubjectMeta{
			Org:  types.Ptr(""),
			Unit: types.Ptr("Security"),
		}
		renewed, err := m.RenewCA(context.Background(), caRow.CertKey, schema.RenewCertRequest{
			Subject: &renewSubject,
		})
		require.NoError(err)

		parsedRenewed, err := x509.ParseCertificate(renewed.Cert)
		require.NoError(err)
		assert.Empty(parsedRenewed.Subject.Organization)
		assert.Equal([]string{"Security"}, parsedRenewed.Subject.OrganizationalUnit)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(renewed.Subject.ID)))
		assert.Nil(storedSubject.Org)
		assert.Equal("Security", types.Value(storedSubject.Unit))
	})

	t.Run("RenewCACarriesForwardSAN", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		rootSigner, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_san",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		currentCA, err := cert.New(
			cert.WithCommonName("renew_ca"),
			cert.WithOrganization("Example Org", "Operations"),
			cert.WithRSAKey(0),
			cert.WithCA(),
			cert.WithExpiry(2*time.Hour),
			cert.WithSigner(rootSigner),
			cert.WithSAN("ca.example.test", "127.0.0.1"),
		)
		require.NoError(err)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))

		var subjectRow schema.Subject
		require.NoError(m.Insert(context.Background(), &subjectRow, currentCA.SubjectMeta()))

		certValue := currentCA.SchemaCert()
		certValue.SubjectID = types.Ptr(subjectRow.ID)
		certValue.Signer = &rootRow.CertKey

		var caRow schema.Cert
		require.NoError(m.Insert(context.Background(), &caRow, certValue))

		renewed, err := m.RenewCA(context.Background(), caRow.CertKey, schema.RenewCertRequest{})
		require.NoError(err)
		require.NotNil(renewed)

		parsedRenewed, err := x509.ParseCertificate(renewed.Cert)
		require.NoError(err)
		assert.Equal([]string{"ca.example.test"}, parsedRenewed.DNSNames)
		if assert.Len(parsedRenewed.IPAddresses, 1) {
			assert.Equal("127.0.0.1", parsedRenewed.IPAddresses[0].String())
		}
		assert.ElementsMatch([]string{"ca.example.test", "127.0.0.1"}, renewed.SAN)
	})

	t.Run("RenewCARejectsRootCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_root",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))

		renewed, err := m.RenewCA(context.Background(), rootRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: root certificate cannot be renewed")
	})

	t.Run("RenewCARejectsLeafCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_leaf",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		renewed, err := m.RenewCA(context.Background(), leafRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: certificate is not a certificate authority")
	})

	t.Run("RenewCARejectsDisabledRoot", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_disabled_root",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "renew_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_ca_renew_disabled_root.cert SET enabled = FALSE WHERE name = CHR(36) || 'root' || CHR(36)`))

		renewed, err := m.RenewCA(context.Background(), caRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrConflict)
		assert.EqualError(err, "Conflict: certificate authority is disabled")
	})

	t.Run("RenewCARejectsDisabledCertificateAuthority", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_ca_renew_disabled_current",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "renew_ca", Expiry: 2 * time.Hour})
		require.NoError(err)

		enabled := false
		updated, err := m.UpdateCert(context.Background(), caRow.CertKey, schema.CertMeta{Enabled: &enabled})
		require.NoError(err)
		require.NotNil(updated)

		renewed, err := m.RenewCA(context.Background(), caRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrConflict)
		assert.EqualError(err, "Conflict: certificate authority is disabled")
	})
}
