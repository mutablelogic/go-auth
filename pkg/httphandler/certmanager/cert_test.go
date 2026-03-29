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
	types "github.com/mutablelogic/go-server/pkg/types"
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

	t.Run("CertByCAHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CertByCAHandler(nil)

		assert.Equal("cert/{name}", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("Get latest certificate", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 3) {
				assert.Equal("name", spec.Get.Parameters[0].Name)
				assert.Equal("chain", spec.Get.Parameters[1].Name)
				assert.Equal("private", spec.Get.Parameters[2].Name)
			}
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Create certificate from CA name", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
			if assert.Len(spec.Post.Parameters, 1) {
				assert.Equal("name", spec.Post.Parameters[0].Name)
			}
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Patch) {
			assert.Equal("Update latest certificate", spec.Patch.Summary)
			assert.NotNil(spec.Patch.RequestBody)
			if assert.Len(spec.Patch.Parameters, 1) {
				assert.Equal("name", spec.Patch.Parameters[0].Name)
			}
		}
	})

	t.Run("CertByCAKeyHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CertByCAKeyHandler(nil)

		assert.Equal("cert/{name}/{serial}", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Get) {
			assert.Equal("Get certificate by version", spec.Get.Summary)
			if assert.Len(spec.Get.Parameters, 4) {
				assert.Equal("name", spec.Get.Parameters[0].Name)
				assert.Equal("serial", spec.Get.Parameters[1].Name)
				assert.Equal("chain", spec.Get.Parameters[2].Name)
				assert.Equal("private", spec.Get.Parameters[3].Name)
			}
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Create certificate from CA version", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
			if assert.Len(spec.Post.Parameters, 2) {
				assert.Equal("name", spec.Post.Parameters[0].Name)
				assert.Equal("serial", spec.Post.Parameters[1].Name)
			}
		}
		if assert.NotNil(spec) && assert.NotNil(spec.Patch) {
			assert.Equal("Update certificate by version", spec.Patch.Summary)
			assert.NotNil(spec.Patch.RequestBody)
			if assert.Len(spec.Patch.Parameters, 2) {
				assert.Equal("name", spec.Patch.Parameters[0].Name)
				assert.Equal("serial", spec.Patch.Parameters[1].Name)
			}
		}
	})

	t.Run("CertRenewByNameHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CertRenewByNameHandler(nil)

		assert.Equal("cert/{name}/renew", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Renew latest certificate", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
			if assert.Len(spec.Post.Parameters, 1) {
				assert.Equal("name", spec.Post.Parameters[0].Name)
			}
		}
	})

	t.Run("CertRenewByKeyHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CertRenewByKeyHandler(nil)

		assert.Equal("cert/{name}/{serial}/renew", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Renew certificate by version", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
			if assert.Len(spec.Post.Parameters, 2) {
				assert.Equal("name", spec.Post.Parameters[0].Name)
				assert.Equal("serial", spec.Post.Parameters[1].Name)
			}
		}
	})

	t.Run("CAHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CAHandler(nil)

		assert.Equal("ca", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Create certificate authority", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
		}
	})

	t.Run("CAByNameRenewHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CAByNameRenewHandler(nil)

		assert.Equal("ca/{name}/renew", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Renew latest certificate authority", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
			if assert.Len(spec.Post.Parameters, 1) {
				assert.Equal("name", spec.Post.Parameters[0].Name)
			}
		}
	})

	t.Run("CAByKeyRenewHandlerPath", func(t *testing.T) {
		assert := assert.New(t)

		path, _, spec := CAByKeyRenewHandler(nil)

		assert.Equal("ca/{name}/{serial}/renew", path)
		if assert.NotNil(spec) && assert.NotNil(spec.Post) {
			assert.Equal("Renew certificate authority by version", spec.Post.Summary)
			assert.NotNil(spec.Post.RequestBody)
			if assert.Len(spec.Post.Parameters, 2) {
				assert.Equal("name", spec.Post.Parameters[0].Name)
				assert.Equal("serial", spec.Post.Parameters[1].Name)
			}
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
		assert.Empty(result.Body[0].SAN)
	})

	t.Run("ListCertificatesIncludesSAN", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		_, err = manager.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:   "leaf_cert",
			Expiry: time.Hour,
			SAN:    []string{"api.example.test", "*.example.test", "127.0.0.1"},
		}, caRow.CertKey)
		require.NoError(err)

		_, handler, _ := CertHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert?is_ca=false&limit=10", nil)
		req.Header.Set("Accept", "application/json")

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.CertList
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		require.Len(result.Body, 1)
		assert.Equal("leaf_cert", result.Body[0].Name)
		assert.ElementsMatch([]string{"api.example.test", "*.example.test", "127.0.0.1"}, result.Body[0].SAN)
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

	t.Run("CreateCertificateFromCAName", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		path, handler, _ := CertByCAHandler(manager)
		assert.Equal("cert/{name}", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/issuer_ca", strings.NewReader(`{"name":"leaf_cert","expiry":3600000000000,"san":["api.example.test","127.0.0.1"],"tags":["ops"]}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", caRow.Name)

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.False(result.IsCA)
		require.NotNil(result.Signer)
		assert.Equal(caRow.Name, result.Signer.Name)
		assert.Equal(caRow.Serial, result.Signer.Serial)
		assert.Equal([]string{"ops"}, result.Tags)
		assert.ElementsMatch([]string{"api.example.test", "127.0.0.1"}, result.SAN)
		require.NotNil(result.Subject)
		require.NotNil(result.Subject.CommonName)
		assert.Equal("leaf_cert", *result.Subject.CommonName)
	})

	t.Run("CreateCertificateFromCAKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)

		path, handler, _ := CertByCAKeyHandler(manager)
		assert.Equal("cert/{name}/{serial}", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/issuer_ca/"+caRow.Serial, strings.NewReader(`{"name":"leaf_cert","expiry":3600000000000}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", caRow.Name)
		req.SetPathValue("serial", caRow.Serial)

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		require.NotNil(result.Signer)
		assert.Equal(caRow.Name, result.Signer.Name)
		assert.Equal(caRow.Serial, result.Signer.Serial)
	})

	t.Run("GetLatestCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		path, handler, _ := CertByCAHandler(manager)
		assert.Equal("cert/{name}", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert/leaf_cert", nil)
		req.Header.Set("Accept", "application/json")
		req.SetPathValue("name", leafRow.Name)

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.CertBundle
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.Equal(leafRow.Serial, result.Serial)
		assert.Empty(result.Chain)
		assert.Empty(result.Key)
	})

	t.Run("GetLatestCertificateIncludesChainAndPrivateKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		path, handler, _ := CertByCAHandler(manager)
		assert.Equal("cert/{name}", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert/leaf_cert?chain=true&private=true", nil)
		req.Header.Set("Accept", "application/json")
		req.SetPathValue("name", leafRow.Name)

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.CertBundle
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.NotEmpty(result.Key)
		require.Len(result.Chain, 2)
		assert.Equal("issuer_ca", result.Chain[0].Name)
		assert.Equal(schema.RootCertName, result.Chain[1].Name)
	})

	t.Run("GetCertificateByVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		path, handler, _ := CertByCAKeyHandler(manager)
		assert.Equal("cert/{name}/{serial}", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert/leaf_cert/"+leafRow.Serial, nil)
		req.Header.Set("Accept", "application/json")
		req.SetPathValue("name", leafRow.Name)
		req.SetPathValue("serial", leafRow.Serial)

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.CertBundle
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.Equal(leafRow.Serial, result.Serial)
	})

	t.Run("GetLatestCertificateRejectsDisabledCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		updated, err := manager.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{Enabled: types.Ptr(false)})
		require.NoError(err)
		require.NotNil(updated)

		_, handler, _ := CertByCAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert/leaf_cert", nil)
		req.Header.Set("Accept", "application/json")
		req.SetPathValue("name", leafRow.Name)

		handler(res, req)

		require.Equal(http.StatusConflict, res.Code)
		assert.Contains(res.Body.String(), "certificate is disabled")
	})

	t.Run("GetCertificateByVersionRejectsDisabledCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		updated, err := manager.UpdateCert(context.Background(), leafRow.CertKey, schema.CertMeta{Enabled: types.Ptr(false)})
		require.NoError(err)
		require.NotNil(updated)

		_, handler, _ := CertByCAKeyHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/cert/leaf_cert/"+leafRow.Serial, nil)
		req.Header.Set("Accept", "application/json")
		req.SetPathValue("name", leafRow.Name)
		req.SetPathValue("serial", leafRow.Serial)

		handler(res, req)

		require.Equal(http.StatusConflict, res.Code)
		assert.Contains(res.Body.String(), "certificate is disabled")
	})

	t.Run("UpdateLatestCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		_, handler, _ := CertByCAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/cert/leaf_cert", strings.NewReader(`{"enabled":false,"tags":["ops","prod"]}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", leafRow.Name)

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.Equal(leafRow.Serial, result.Serial)
		require.NotNil(result.Enabled)
		assert.False(*result.Enabled)
		assert.Equal([]string{"ops", "prod"}, result.Tags)
	})

	t.Run("UpdateCertificateByVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		_, handler, _ := CertByCAKeyHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/cert/leaf_cert/"+leafRow.Serial, strings.NewReader(`{"tags":[]}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", leafRow.Name)
		req.SetPathValue("serial", leafRow.Serial)

		handler(res, req)

		require.Equal(http.StatusOK, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.Equal(leafRow.Serial, result.Serial)
		assert.Empty(result.Tags)
	})

	t.Run("RenewLatestCertificate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour, Tags: []string{"leaf"}}, caRow.CertKey)
		require.NoError(err)

		_, handler, _ := CertRenewByNameHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/leaf_cert/renew", strings.NewReader(`{"expiry":1800000000000}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", leafRow.Name)

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.NotEmpty(result.Serial)
		assert.NotEqual(leafRow.Serial, result.Serial)
		assert.Equal([]string{"leaf"}, result.Tags)
		require.NotNil(result.Enabled)
		assert.True(*result.Enabled)

		var oldRow schema.Cert
		require.NoError(manager.Get(context.Background(), &oldRow, leafRow.CertKey))
		require.NotNil(oldRow.Enabled)
		assert.False(*oldRow.Enabled)
	})

	t.Run("RenewCertificateByVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)
		leafRow, err := manager.CreateCert(context.Background(), schema.CreateCertRequest{Name: "leaf_cert", Expiry: time.Hour}, caRow.CertKey)
		require.NoError(err)

		_, handler, _ := CertRenewByKeyHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/leaf_cert/"+leafRow.Serial+"/renew", strings.NewReader(`{}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", leafRow.Name)
		req.SetPathValue("serial", leafRow.Serial)

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("leaf_cert", result.Name)
		assert.NotEmpty(result.Serial)
		assert.NotEqual(leafRow.Serial, result.Serial)
		require.NotNil(result.Enabled)
		assert.True(*result.Enabled)
	})

	t.Run("CreateCertificateRejectsBadBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CertByCAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/issuer_ca", strings.NewReader(`{"name":`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "issuer_ca")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unexpected EOF")
	})

	t.Run("UpdateCertificateRejectsBadBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CertByCAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPatch, "/cert/leaf_cert", strings.NewReader(`{"enabled":`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "leaf_cert")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unexpected EOF")
	})

	t.Run("CreateCertificateRejectsMissingCASerialPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CertByCAKeyHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/issuer_ca", strings.NewReader(`{"name":"leaf_cert","expiry":3600000000000}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "issuer_ca")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "serial is required")
	})

	t.Run("RenewCertificateRejectsBadBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CertRenewByNameHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/leaf_cert/renew", strings.NewReader(`{"expiry":`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "leaf_cert")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unexpected EOF")
	})

	t.Run("RenewCertificateRejectsMissingSerialPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CertRenewByKeyHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/cert/leaf_cert/renew", strings.NewReader(`{}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "leaf_cert")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "serial is required")
	})

	t.Run("CreateCertificateAuthority", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		path, handler, _ := CAHandler(manager)
		assert.Equal("ca", path)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ca", strings.NewReader(`{"name":"issuer_ca","expiry":3600000000000}`))
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
		require.NotNil(result.Subject.CommonName)
		assert.Equal("issuer_ca", *result.Subject.CommonName)
		assert.Equal("Example Org", valueOrEmpty(result.Subject.Org))
		require.NotNil(result.Subject.Name)
		assert.Equal("CN=issuer_ca,O=Example Org", *result.Subject.Name)
		assert.NotNil(result.Signer)
		assert.Equal(schema.RootCertName, result.Signer.Name)
	})

	t.Run("CreateCertificateAuthorityRejectsBadBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CAHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ca", strings.NewReader(`{"name":`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unexpected EOF")
	})

	t.Run("RenewLatestCertificateAuthority", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour, Tags: []string{"ops"}})
		require.NoError(err)

		_, handler, _ := CAByNameRenewHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ca/issuer_ca/renew", strings.NewReader(`{}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", caRow.Name)

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("issuer_ca", result.Name)
		assert.NotEmpty(result.Serial)
		assert.NotEqual(caRow.Serial, result.Serial)
		assert.True(result.IsCA)
		assert.Equal([]string{"ops"}, result.Tags)
	})

	t.Run("RenewCertificateAuthorityByVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		caRow, err := manager.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: 2 * time.Hour})
		require.NoError(err)

		_, handler, _ := CAByKeyRenewHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ca/issuer_ca/"+caRow.Serial+"/renew", strings.NewReader(`{}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", caRow.Name)
		req.SetPathValue("serial", caRow.Serial)

		handler(res, req)

		require.Equal(http.StatusCreated, res.Code)

		var result schema.Cert
		require.NoError(json.Unmarshal(res.Body.Bytes(), &result))
		assert.Equal("issuer_ca", result.Name)
		assert.NotEmpty(result.Serial)
		assert.NotEqual(caRow.Serial, result.Serial)
		assert.True(result.IsCA)
		require.NotNil(result.Enabled)
		assert.True(*result.Enabled)
	})

	t.Run("RenewCertificateAuthorityRejectsBadBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CAByNameRenewHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ca/issuer_ca/renew", strings.NewReader(`{"tags":`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "issuer_ca")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "unexpected EOF")
	})

	t.Run("RenewCertificateAuthorityRejectsMissingSerialPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		manager := newHTTPTestManager(t)
		_, handler, _ := CAByKeyRenewHandler(manager)

		res := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/ca/issuer_ca/renew", strings.NewReader(`{}`))
		req.Header.Set("Accept", "application/json")
		req.Header.Set("Content-Type", "application/json")
		req.SetPathValue("name", "issuer_ca")

		handler(res, req)

		require.Equal(http.StatusBadRequest, res.Code)
		assert.Contains(res.Body.String(), "serial is required")
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
		req := httptest.NewRequest(http.MethodPost, "/ca", strings.NewReader(`{"name":"issuer_ca","expiry":3600000000000}`))
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
