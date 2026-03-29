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
	"math/big"
	"net"
	"testing"
	"time"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/certmanager"
	schema "github.com/djthorpe/go-auth/schema/cert"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestCert_001(t *testing.T) {
	t.Run("ListCerts", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_list",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		_, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "alpha_ca", Expiry: time.Hour})
		require.NoError(err)
		_, err = m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "beta_ca", Expiry: time.Hour})
		require.NoError(err)

		result, err := m.ListCerts(context.Background(), schema.CertListRequest{})
		require.NoError(err)
		require.NotNil(result)

		assert.Equal(uint64(2), result.Count)
		require.Len(result.Body, 2)
		assert.Equal(schema.CertListRequest{}, result.CertListRequest)

		names := make([]string, 0, len(result.Body))
		for _, cert := range result.Body {
			names = append(names, cert.Name)
		}
		assert.ElementsMatch([]string{"alpha_ca", "beta_ca"}, names)
	})

	t.Run("ListCertsFiltersEffectiveTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_list_tags",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_list_tags.cert SET tags = ARRAY['root-tag'] WHERE name = CHR(36) || 'root' || CHR(36)`))

		_, err := m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:   "tagged_ca",
			Expiry: time.Hour,
			Tags:   []string{"child-tag", "extra-tag"},
		})
		require.NoError(err)

		_, err = m.CreateCA(context.Background(), schema.CreateCertRequest{
			Name:   "other_ca",
			Expiry: time.Hour,
			Tags:   []string{"child-tag"},
		})
		require.NoError(err)

		result, err := m.ListCerts(context.Background(), schema.CertListRequest{Tags: []string{"root-tag", "extra-tag"}})
		require.NoError(err)
		require.NotNil(result)

		assert.Equal(uint64(1), result.Count)
		require.Len(result.Body, 1)
		assert.Equal([]string{"root-tag", "extra-tag"}, result.CertListRequest.Tags)
		assert.Equal("tagged_ca", result.Body[0].Name)
		assert.ElementsMatch([]string{"child-tag", "extra-tag", "root-tag"}, result.Body[0].EffectiveTags)
	})

	t.Run("ListCertsRejectsInvalidTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_list_invalid_tags",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		result, err := m.ListCerts(context.Background(), schema.CertListRequest{Tags: []string{"bad tag"}})
		require.Error(err)
		assert.Nil(result)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, `Bad Request: tag "bad tag" is invalid`)
	})

	t.Run("CreateCertDefaultsToCASubjectAndCapsExpiry", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_default",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		require.NotNil(caRow)

		parsedCA, err := x509.ParseCertificate(caRow.Cert)
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert"}, caRow.CertKey)
		require.NoError(err)
		require.NotNil(leafRow)

		assert.Equal("leaf_cert", leafRow.Name)
		assert.NotEmpty(leafRow.Serial)
		assert.False(leafRow.IsCA)
		assert.True(types.Value(leafRow.Enabled))
		assert.Empty(leafRow.Tags)
		assert.Empty(leafRow.EffectiveTags)
		require.NotNil(leafRow.Signer)
		assert.Equal(caRow.CertKey, *leafRow.Signer)

		parsedLeaf, err := x509.ParseCertificate(leafRow.Cert)
		require.NoError(err)
		assert.Equal("leaf_cert", parsedLeaf.Subject.CommonName)
		assert.Equal(parsedCA.Subject.Organization, parsedLeaf.Subject.Organization)
		assert.Equal(parsedCA.Subject.String(), parsedLeaf.Issuer.String())
		assert.False(parsedLeaf.NotAfter.After(parsedCA.NotAfter))
		assert.True(parsedLeaf.NotAfter.After(parsedLeaf.NotBefore))
		assert.LessOrEqual(parsedLeaf.NotAfter.Sub(parsedLeaf.NotBefore), 2*time.Hour)
		assert.Empty(parsedLeaf.DNSNames)
		assert.Empty(parsedLeaf.IPAddresses)
		assert.Empty(leafRow.SAN)
	})

	t.Run("CreateCertIncludesSAN", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_san",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 24 * time.Hour})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:   "leaf_cert",
			Expiry: 2 * time.Hour,
			SAN:    []string{"api.example.test", "*.example.test", "127.0.0.1"},
		}, caRow.CertKey)
		require.NoError(err)
		require.NotNil(leafRow)

		parsedLeaf, err := x509.ParseCertificate(leafRow.Cert)
		require.NoError(err)
		assert.ElementsMatch([]string{"api.example.test", "*.example.test", "127.0.0.1"}, leafRow.SAN)
		assert.ElementsMatch([]string{"api.example.test", "*.example.test"}, parsedLeaf.DNSNames)
		if assert.Len(parsedLeaf.IPAddresses, 1) {
			assert.True(parsedLeaf.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
		}
	})

	t.Run("CreateCertRejectsCIDRSAN", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_cidr",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 24 * time.Hour})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:   "leaf_cert",
			Expiry: time.Hour,
			SAN:    []string{"10.0.0.0/24"},
		}, caRow.CertKey)
		require.Error(err)
		assert.Nil(leafRow)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, `Bad Request: san entry "10.0.0.0/24" is a CIDR range and is not supported for certificates`)
	})

	t.Run("CreateCertUsesExplicitSubjectAndExpiry", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_custom",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 24 * time.Hour})
		require.NoError(err)

		subject := schema.SubjectMeta{
			Org:           types.Ptr("Example Org"),
			Unit:          types.Ptr("Security"),
			Country:       types.Ptr("US"),
			State:         types.Ptr("California"),
			City:          types.Ptr("San Francisco"),
			StreetAddress: types.Ptr("1 Example Way"),
			PostalCode:    types.Ptr("94105"),
		}

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:    "custom_leaf",
			Expiry:  2 * time.Hour,
			Subject: &subject,
			Tags:    []string{"leaf-tag", " leaf-extra ", "leaf-tag"},
		}, caRow.CertKey)
		require.NoError(err)
		require.NotNil(leafRow)

		parsedLeaf, err := x509.ParseCertificate(leafRow.Cert)
		require.NoError(err)
		assert.Equal("custom_leaf", parsedLeaf.Subject.CommonName)
		assert.Equal(2*time.Hour, parsedLeaf.NotAfter.Sub(parsedLeaf.NotBefore))
		assert.True(types.Value(leafRow.Enabled))
		assert.Equal([]string{"leaf-tag", "leaf-extra"}, leafRow.Tags)
		assert.ElementsMatch([]string{"leaf-extra", "leaf-tag"}, leafRow.EffectiveTags)
	})

	t.Run("CreateCertMergesExplicitSubjectWithCASubject", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_merge_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caSubject := schema.SubjectMeta{
			Org:     types.Ptr("Example Org"),
			Unit:    types.Ptr("Operations"),
			Country: types.Ptr("GB"),
		}
		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 24 * time.Hour, Subject: &caSubject})
		require.NoError(err)

		leafSubject := schema.SubjectMeta{
			Unit: types.Ptr("Security"),
			City: types.Ptr("London"),
		}

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:    "merged_leaf",
			Expiry:  time.Hour,
			Subject: &leafSubject,
		}, caRow.CertKey)
		require.NoError(err)

		parsedLeaf, err := x509.ParseCertificate(leafRow.Cert)
		require.NoError(err)
		assert.Equal([]string{"Example Org"}, parsedLeaf.Subject.Organization)
		assert.Equal([]string{"Security"}, parsedLeaf.Subject.OrganizationalUnit)
		assert.Equal([]string{"GB"}, parsedLeaf.Subject.Country)
		assert.Equal([]string{"London"}, parsedLeaf.Subject.Locality)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(leafRow.Subject.ID)))
		assert.Equal("Example Org", types.Value(storedSubject.Org))
		assert.Equal("Security", types.Value(storedSubject.Unit))
		assert.Equal("GB", types.Value(storedSubject.Country))
		assert.Equal("London", types.Value(storedSubject.City))
	})

	t.Run("CreateCertAllowsExplicitlyClearingInheritedSubjectFields", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_clear_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caSubject := schema.SubjectMeta{
			Org:  types.Ptr("Example Org"),
			Unit: types.Ptr("Operations"),
		}
		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 24 * time.Hour, Subject: &caSubject})
		require.NoError(err)

		leafSubject := schema.SubjectMeta{
			Org:  types.Ptr(""),
			Unit: types.Ptr("Security"),
		}

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:    "cleared_leaf",
			Expiry:  time.Hour,
			Subject: &leafSubject,
		}, caRow.CertKey)
		require.NoError(err)

		parsedLeaf, err := x509.ParseCertificate(leafRow.Cert)
		require.NoError(err)
		assert.Empty(parsedLeaf.Subject.Organization)
		assert.Equal([]string{"Security"}, parsedLeaf.Subject.OrganizationalUnit)

		var storedSubject schema.Subject
		require.NoError(m.Get(context.Background(), &storedSubject, schema.SubjectID(leafRow.Subject.ID)))
		assert.Nil(storedSubject.Org)
		assert.Equal("Security", types.Value(storedSubject.Unit))
	})

	t.Run("CreateCertRejectsDisabledCA", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_disabled_ca",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_leaf_disabled_ca.cert SET enabled = FALSE WHERE name = 'issuer_ca'`))

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "disabled_leaf", Expiry: time.Hour}, caRow.CertKey)
		require.Error(err)
		assert.Nil(leafRow)
		assert.ErrorIs(err, httpresponse.ErrConflict)
	})

	t.Run("CreateCertRejectsRootSigner", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_root_signer",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "root_signed_leaf", Expiry: time.Hour}, rootRow.CertKey)
		require.Error(err)
		assert.Nil(leafRow)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: root certificate cannot sign leaf certificates")
	})

	t.Run("CreateCertRejectsLeafSigner", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_leaf_non_ca_signer",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		leafSigner, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_signer", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, leafSigner.CertKey)
		require.Error(err)
		assert.Nil(leafRow)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: signer is not a certificate authority")
	})

	t.Run("GetCertChainReturnsLeafToRootWithoutPrivateMaterial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_chain",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		require.NotNil(caRow)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)
		require.NotNil(leafRow)

		chain, err := m.GetCertChain(context.Background(), leafRow.CertKey)
		require.NoError(err)
		require.Len(chain, 3)

		assert.Equal("leaf_cert", chain[0].Name)
		assert.Equal("issuer_ca", chain[1].Name)
		assert.Equal(schema.RootCertName, chain[2].Name)

		require.NotNil(chain[0].Signer)
		assert.Equal(caRow.CertKey, *chain[0].Signer)
		require.NotNil(chain[1].Signer)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))
		assert.Equal(rootRow.CertKey, *chain[1].Signer)
		assert.Nil(chain[2].Signer)

		for _, row := range chain {
			assert.NotEmpty(row.Cert)
		}
	})

	t.Run("GetCertChainRejectsMissingCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_chain_missing",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		chain, err := m.GetCertChain(context.Background(), schema.CertKey{Name: "missing_leaf", Serial: "1"})
		require.Error(err)
		assert.Nil(chain)
		assert.ErrorIs(err, pg.ErrNotFound)
	})

	t.Run("GetPrivateKeyReturnsLeafWithStoredKeyMaterial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_get_private_key_leaf",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		result, err := m.GetPrivateKey(context.Background(), leafRow.CertKey)
		require.NoError(err)
		require.NotNil(result)

		assert.Equal(leafRow.CertKey, result.CertKey)
		assert.False(result.IsCA)
		assert.NotEmpty(result.Key)
		assert.Zero(result.PV)

		var stored schema.CertWithPrivateKey
		require.NoError(m.Get(context.Background(), &stored, schema.PrivateCertKey(leafRow.CertKey)))
		assert.NotEqual(stored.Key, result.Key)
		assert.NotZero(stored.PV)

		parsedKeyAny, err := x509.ParsePKCS8PrivateKey(result.Key)
		require.NoError(err)
		_, ok := parsedKeyAny.(*rsa.PrivateKey)
		assert.True(ok)
	})

	t.Run("GetPrivateKeyRejectsRootCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_get_private_key_root",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))

		result, err := m.GetPrivateKey(context.Background(), rootRow.CertKey)
		require.Error(err)
		assert.Nil(result)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: root certificate private key cannot be retrieved")
	})

	t.Run("GetPrivateKeyRejectsCertificateAuthority", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_get_private_key_ca",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		result, err := m.GetPrivateKey(context.Background(), caRow.CertKey)
		require.Error(err)
		assert.Nil(result)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: certificate authority private key cannot be retrieved")
	})

	t.Run("RenewCertDisablesCurrentAndCreatesNewSerial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour, Tags: []string{"ca-tag"}})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: 90 * time.Minute, Tags: []string{"leaf-tag"}}, caRow.CertKey)
		require.NoError(err)

		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{
			Expiry: 30 * time.Minute,
			Tags:   []string{"renewed-tag"},
		})
		require.NoError(err)
		require.NotNil(renewed)

		assert.Equal(leafRow.Name, renewed.Name)
		assert.Equal(nextSerialString(t, leafRow.Serial), renewed.Serial)
		assert.Equal([]string{"renewed-tag"}, renewed.Tags)
		assert.True(types.Value(renewed.Enabled))
		require.NotNil(renewed.Signer)
		assert.Equal(caRow.CertKey, *renewed.Signer)

		parsedRenewed, err := x509.ParseCertificate(renewed.Cert)
		require.NoError(err)
		assert.Equal("leaf_cert", parsedRenewed.Subject.CommonName)
		assert.Equal(30*time.Minute, parsedRenewed.NotAfter.Sub(parsedRenewed.NotBefore))

		var oldRow schema.Cert
		require.NoError(m.Get(context.Background(), &oldRow, leafRow.CertKey))
		assert.False(types.Value(oldRow.Enabled))

		var newRow schema.Cert
		require.NoError(m.Get(context.Background(), &newRow, renewed.CertKey))
		assert.True(types.Value(newRow.Enabled))
		assert.Equal([]string{"renewed-tag"}, newRow.Tags)
		assert.ElementsMatch([]string{"ca-tag", "renewed-tag"}, newRow.EffectiveTags)
	})

	t.Run("RenewCertMergesExplicitSubjectWithCurrentSubject", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_merge_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)

		leafSubject := schema.SubjectMeta{
			Org:     types.Ptr("Example Org"),
			Unit:    types.Ptr("Operations"),
			Country: types.Ptr("GB"),
		}
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:    "leaf_cert",
			Expiry:  time.Hour,
			Subject: &leafSubject,
		}, caRow.CertKey)
		require.NoError(err)

		renewSubject := schema.SubjectMeta{
			Unit: types.Ptr("Security"),
			City: types.Ptr("London"),
		}
		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{
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

	t.Run("RenewCertCarriesForwardSAN", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_san",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:   "leaf_cert",
			Expiry: time.Hour,
			SAN:    []string{"api.example.test", "*.example.test", "127.0.0.1"},
		}, caRow.CertKey)
		require.NoError(err)

		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{})
		require.NoError(err)
		require.NotNil(renewed)

		parsedRenewed, err := x509.ParseCertificate(renewed.Cert)
		require.NoError(err)
		assert.ElementsMatch([]string{"api.example.test", "*.example.test"}, parsedRenewed.DNSNames)
		if assert.Len(parsedRenewed.IPAddresses, 1) {
			assert.Equal("127.0.0.1", parsedRenewed.IPAddresses[0].String())
		}
		assert.ElementsMatch([]string{"api.example.test", "*.example.test", "127.0.0.1"}, renewed.SAN)
	})

	t.Run("RenewCertAllowsExplicitlyClearingInheritedSubjectFields", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_clear_subject",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)

		leafSubject := schema.SubjectMeta{
			Org:  types.Ptr("Example Org"),
			Unit: types.Ptr("Operations"),
		}
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:    "leaf_cert",
			Expiry:  time.Hour,
			Subject: &leafSubject,
		}, caRow.CertKey)
		require.NoError(err)

		renewSubject := schema.SubjectMeta{
			Org:  types.Ptr(""),
			Unit: types.Ptr("Security"),
		}
		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{
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

	t.Run("RenewCertRejectsRootCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_root",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))

		renewed, err := m.RenewCert(context.Background(), rootRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: root certificate cannot be renewed")
	})

	t.Run("RenewCertRejectsCertificateAuthority", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_ca",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		renewed, err := m.RenewCert(context.Background(), caRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: certificate is not a leaf certificate")
	})

	t.Run("RenewCertRejectsDisabledSigner", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_disabled_signer",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		require.NoError(m.Exec(context.Background(), `UPDATE cert_test_renew_leaf_disabled_signer.cert SET enabled = FALSE WHERE name = 'issuer_ca'`))

		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrConflict)
		assert.EqualError(err, "Conflict: certificate is disabled")
	})

	t.Run("RenewCertRejectsDisabledCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_disabled_current",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		enabled := false
		updated, err := m.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{Enabled: &enabled})
		require.NoError(err)
		require.NotNil(updated)

		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrConflict)
		assert.EqualError(err, "Conflict: certificate is disabled")
	})

	t.Run("RenewCertRejectsRenewingDisabledPreviousVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_renew_leaf_duplicate_serial",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		_, err = m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{})
		require.NoError(err)

		renewed, err := m.RenewCert(context.Background(), leafRow.CertKey, schema.RenewCertRequest{})
		require.Error(err)
		assert.Nil(renewed)
		assert.ErrorIs(err, httpresponse.ErrConflict)
		assert.EqualError(err, "Conflict: certificate is disabled")
	})

	t.Run("UpdateCertUpdatesRawTagsAndEnabled", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_update_leaf",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour, Tags: []string{"ca-tag"}})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		enabled := false
		updated, err := m.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{
			Enabled: &enabled,
			Tags:    []string{" leaf-tag ", "leaf-extra", "leaf-tag"},
		})
		require.NoError(err)
		require.NotNil(updated)

		assert.False(types.Value(updated.Enabled))
		assert.Equal([]string{"leaf-tag", "leaf-extra"}, updated.Tags)
		assert.ElementsMatch([]string{"ca-tag", "leaf-extra", "leaf-tag"}, updated.EffectiveTags)

		var stored schema.Cert
		require.NoError(m.Get(context.Background(), &stored, leafRow.CertKey))
		assert.False(types.Value(stored.Enabled))
		assert.Equal([]string{"leaf-tag", "leaf-extra"}, stored.Tags)
		assert.ElementsMatch([]string{"ca-tag", "leaf-extra", "leaf-tag"}, stored.EffectiveTags)
	})

	t.Run("UpdateCertCanClearTagsOnly", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_update_clear_tags",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour, Tags: []string{"ca-tag"}})
		require.NoError(err)

		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		_, err = m.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{Tags: []string{"leaf-tag"}})
		require.NoError(err)

		updated, err := m.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{Tags: []string{}})
		require.NoError(err)
		require.NotNil(updated)

		assert.Empty(updated.Tags)
		assert.ElementsMatch([]string{"ca-tag"}, updated.EffectiveTags)
	})

	t.Run("UpdateCertRejectsEmptyPatch", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_update_empty",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		caRow, err := m.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := m.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		updated, err := m.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{})
		require.Error(err)
		assert.Nil(updated)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: nothing to update")
	})

	t.Run("UpdateCertRejectsRootCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
		m := newCustomSchemaManagerWithOpts(t,
			"cert_test_update_root",
			manager.WithPassphrase(1, "root-secret-1"),
			manager.WithRoot(pemValue),
		)

		var rootRow schema.Cert
		require.NoError(m.Get(context.Background(), &rootRow, schema.CertName(schema.RootCertName)))

		enabled := false
		updated, err := m.UpdateCert(context.Background(), rootRow.CertKey, schema.CertMeta{Enabled: &enabled})
		require.Error(err)
		assert.Nil(updated)
		assert.ErrorIs(err, httpresponse.ErrBadRequest)
		assert.EqualError(err, "Bad Request: root certificate cannot be updated")
	})
}

func nextSerialString(t *testing.T, serial string) string {
	t.Helper()
	value, ok := new(big.Int).SetString(serial, 10)
	require.True(t, ok)
	return value.Add(value, big.NewInt(1)).Text(10)
}
