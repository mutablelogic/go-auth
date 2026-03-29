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

package certmanager

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	// Packages
	cert "github.com/djthorpe/go-auth/pkg/cert"
	managerpkg "github.com/djthorpe/go-auth/pkg/certmanager"
	schema "github.com/djthorpe/go-auth/schema/cert"
	test "github.com/mutablelogic/go-pg/pkg/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

var conn test.Conn

func TestMain(m *testing.M) {
	test.Main(m, &conn)
}

func Test_cert_001(t *testing.T) {
	t.Run("CertHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CertHandler(nil)

		assert.Equal("cert", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("List certificates", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 7) {
				assert.Equal("is_ca", spec.Get.Parameters[0].Name)
				assert.Equal("enabled", spec.Get.Parameters[1].Name)
				assert.Equal("tags", spec.Get.Parameters[2].Name)
				assert.Equal("valid", spec.Get.Parameters[3].Name)
			}
		}
	})

	t.Run("CAHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CAHandler(nil)

		assert.Equal("cert/ca", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Create certificate authority", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
		}
	})

	t.Run("ListCertificates", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		require.NotNil(caRow)

		path, handler, _ := CertHandler(manager)
		assert.Equal("cert", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert?is_ca=true&limit=10", nil)
		req.Header.Set("Accept", "application/json")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.CertList
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal(uint64(1), result.Count)
		require.Len(result.Body, 1)
		assert.Equal("issuer_ca", result.Body[0].Name)
		assert.True(result.Body[0].IsCA)
		assert.Equal([]string(nil), result.Body[0].EffectiveTags)
	})

	t.Run("ListCertificatesRejectsBadQuery", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CertHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert?limit=-1", nil)
		req.Header.Set("Accept", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "limit")
	})

	t.Run("CreateCertificateAuthority", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		path, handler, _ := CAHandler(manager)
		assert.Equal("cert/ca", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/ca", strings.NewReader(`{"name":"issuer_ca","expiry":3600000000000}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("issuer_ca", result.Name)
		assert.True(result.IsCA)
		assert.NotEmpty(result.Serial)
		require.NotNil(result.Subject)
		assert.NotZero(result.Subject.ID)
		assert.Equal("Example Org", valueOrEmpty(result.Subject.Org))
		require.NotNil(result.Subject.Name)
		assert.Equal("O=Example Org", *result.Subject.Name)
		assert.NotNil(result.Signer)
		assert.Equal(schema.RootCertName, result.Signer.Name)
	})

	t.Run("CreateCertificateAuthorityRejectsBadBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/ca", strings.NewReader(`{"name":`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unexpected EOF")
	})

	t.Run("CreateCertificateAuthorityRejectsMissingRoot", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		c := conn.Begin(t)
		t.Cleanup(func() { c.Close() })

		manager, err := managerpkg.New(context.Background(), c,
			managerpkg.WithPassphrase(1, "root-secret-1"),
		)
		require.NoError(err)
		require.NoError(manager.Exec(context.Background(), `TRUNCATE cert.subject CASCADE`))

		_, handler, _ := CAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/ca", strings.NewReader(`{"name":"issuer_ca","expiry":3600000000000}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusServiceUnavailable, res.Code)
		assert.Contains(res.Body.String(), "root certificate has not been imported on server")
	})
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func newHTTPTestManager(t *testing.T) *managerpkg.Manager {
	t.Helper()

	c := conn.Begin(t)
	t.Cleanup(func() { c.Close() })

	_, _, _, pemValue := newRootPEMBundle(t, "Example Root CA", "Example Org")
	manager, err := managerpkg.New(context.Background(), c,
		managerpkg.WithPassphrase(1, "root-secret-1"),
	)
	require.NoError(t, err)
	require.NoError(t, manager.Exec(context.Background(), `TRUNCATE cert.subject CASCADE`))
	_, err = manager.InsertRootCert(context.Background(), pemValue)
	require.NoError(t, err)

	return manager
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

	parsed, err := x509.ParseCertificate(root.SchemaCert().Cert.Cert)
	require.NoError(t, err)

	key, ok := root.PrivateKey().(*rsa.PrivateKey)
	require.True(t, ok)

	var pemValue bytes.Buffer
	require.NoError(t, root.Write(&pemValue))
	require.NoError(t, root.WritePrivateKey(&pemValue))

	return root, parsed, key, pemValue.String()
}
