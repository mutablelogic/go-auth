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

package httpclient_test

import (
	"context"
	"crypto/x509"
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	cert "github.com/mutablelogic/go-auth/cert/cert"
	httpclient "github.com/mutablelogic/go-auth/cert/httpclient"
	httphandler "github.com/mutablelogic/go-auth/cert/httphandler"
	certtest "github.com/mutablelogic/go-auth/cert/test"
	types "github.com/mutablelogic/go-server/pkg/types"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	certtest.Main(m, nil)
}

// newClient returns a client of a test server, which serves the handlers
// with the shared manager, and checks every request and response against
// the OpenAPI specification
func newClient(t *testing.T) *httpclient.Client {
	t.Helper()
	mgr, _ := certtest.Begin(t)
	s := test.NewServer(t, httphandler.RegisterHandlers(mgr, false))
	c, err := httpclient.New(s.URL + test.Prefix)
	require.NoError(t, err)
	return c
}

func Test_Client(t *testing.T) {
	ctx := context.Background()
	c := newClient(t)

	// A CA, and its renewal by name and version
	ca, err := c.CreateCA(ctx, cert.CreateCertRequest{Name: "client_ca"})
	require.NoError(t, err)
	assert.True(t, ca.IsCA)
	_, err = c.CreateCA(ctx, cert.CreateCertRequest{Name: "client_ca"})
	assert.ErrorIs(t, err, auth.ErrConflict)

	renewedCA, err := c.RenewCA(ctx, cert.CertKey{Name: "client_ca"}, cert.RenewCertRequest{})
	require.NoError(t, err)
	assert.NotEqual(t, ca.Serial, renewedCA.Serial)
	_, err = c.RenewCA(ctx, renewedCA.CertKey, cert.RenewCertRequest{Expiry: time.Hour})
	require.NoError(t, err)

	// A leaf certificate, with the CA's latest version and with a version
	leaf, err := c.CreateCert(ctx, cert.CreateCertRequest{Name: "client_leaf", SAN: []string{"leaf.example.test"}, Tags: []string{"client"}}, cert.CertKey{Name: "client_ca"})
	require.NoError(t, err)
	assert.Equal(t, "client_ca", types.Value(leaf.Signer).Name)
	other, err := c.CreateCert(ctx, cert.CreateCertRequest{Name: "client_other", Expiry: time.Hour}, ca.CertKey)
	require.NoError(t, err)
	assert.Equal(t, ca.CertKey, types.Value(other.Signer))
	_, err = c.CreateCert(ctx, cert.CreateCertRequest{Name: "client_missing"}, cert.CertKey{Name: "missing_ca"})
	assert.ErrorIs(t, err, auth.ErrNotFound)

	t.Run("Get", func(t *testing.T) {
		bundle, err := c.GetCert(ctx, cert.CertKey{Name: "client_leaf"}, cert.GetCertRequest{Chain: true, Private: true})
		require.NoError(t, err)
		assert.Equal(t, leaf.CertKey, bundle.CertKey)
		require.Len(t, bundle.Chain, 2)
		assert.Equal(t, cert.RootCertName, bundle.Chain[1].Name)
		_, err = x509.ParsePKCS8PrivateKey(bundle.Key)
		assert.NoError(t, err)

		version, err := c.GetCert(ctx, leaf.CertKey, cert.GetCertRequest{})
		require.NoError(t, err)
		assert.Empty(t, version.Key)
		assert.Empty(t, version.Chain)

		_, err = c.GetCert(ctx, cert.CertKey{Name: "client_ca"}, cert.GetCertRequest{Private: true})
		assert.ErrorIs(t, err, auth.ErrBadParameter, "not a CA's private key")
	})

	t.Run("List", func(t *testing.T) {
		list, err := c.ListCerts(ctx, cert.CertListRequest{Tags: []string{"client"}})
		require.NoError(t, err)
		require.Equal(t, uint64(1), list.Count)
		assert.Equal(t, leaf.CertKey, list.Body[0].CertKey)

		limit := uint64(1)
		page, err := c.ListCerts(ctx, cert.CertListRequest{OffsetLimit: cert.OffsetLimit{Limit: &limit}, IsCA: types.Ptr(true)})
		require.NoError(t, err)
		assert.Len(t, page.Body, 1)
		assert.True(t, page.Body[0].IsCA)
	})

	t.Run("Update", func(t *testing.T) {
		updated, err := c.UpdateCert(ctx, cert.CertKey{Name: "client_other"}, cert.CertMeta{Tags: []string{"temp"}})
		require.NoError(t, err)
		assert.Equal(t, []string{"temp"}, updated.Tags)

		// Empty tags remove them
		updated, err = c.UpdateCert(ctx, other.CertKey, cert.CertMeta{Tags: []string{}})
		require.NoError(t, err)
		assert.Empty(t, updated.Tags)

		// Disabled, it can't be got
		updated, err = c.UpdateCert(ctx, other.CertKey, cert.CertMeta{Enabled: types.Ptr(false)})
		require.NoError(t, err)
		assert.False(t, types.Value(updated.Enabled))
		_, err = c.GetCert(ctx, other.CertKey, cert.GetCertRequest{})
		assert.ErrorIs(t, err, auth.ErrConflict)
	})

	t.Run("Renew", func(t *testing.T) {
		// Signed by the CA's latest version
		renewed, err := c.RenewCert(ctx, cert.CertKey{Name: "client_leaf"}, cert.RenewCertRequest{Expiry: time.Hour})
		require.NoError(t, err)
		assert.NotEqual(t, leaf.Serial, renewed.Serial)
		latest, err := c.GetCert(ctx, cert.CertKey{Name: "client_ca"}, cert.GetCertRequest{})
		require.NoError(t, err)
		assert.Equal(t, latest.CertKey, types.Value(renewed.Signer))

		_, err = c.RenewCert(ctx, renewed.CertKey, cert.RenewCertRequest{})
		require.NoError(t, err)
		_, err = c.RenewCert(ctx, leaf.CertKey, cert.RenewCertRequest{})
		assert.ErrorIs(t, err, auth.ErrConflict, "the first version is disabled")
	})
}
