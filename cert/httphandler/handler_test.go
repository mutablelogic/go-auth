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

package httphandler_test

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	httphandler "github.com/mutablelogic/go-auth/cert/httphandler"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	certtest "github.com/mutablelogic/go-auth/cert/test"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapischema "github.com/mutablelogic/go-server/pkg/openapi/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
	test "github.com/mutablelogic/go-server/test"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestMain(m *testing.M) {
	certtest.Main(m, nil)
}

func Test_CA(t *testing.T) {
	mgr, _ := certtest.Begin(t)
	s := test.NewServer(t, httphandler.RegisterHandlers(mgr, false))

	var ca cert.Certificate
	t.Run("Create", func(t *testing.T) {
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "ca", cert.CreateCertRequest{Name: "handler_ca", Tags: []string{"handler"}}, &ca))
		assert.Equal(t, "handler_ca", ca.Name)
		assert.True(t, ca.IsCA)
		assert.Equal(t, cert.RootCertName, types.Value(ca.Signer).Name)
		assert.Equal(t, []string{"handler"}, ca.Tags)

		status, _ := s.Do(t, http.MethodPost, "ca", cert.CreateCertRequest{Name: "handler_ca"})
		assert.Equal(t, http.StatusConflict, status, "it exists")
		status, _ = s.Do(t, http.MethodPost, "ca", cert.CreateCertRequest{})
		assert.Equal(t, http.StatusBadRequest, status, "no name")
	})

	t.Run("Renew", func(t *testing.T) {
		var renewed cert.Certificate
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "ca/handler_ca/renew", cert.RenewCertRequest{}, &renewed))
		assert.Equal(t, ca.Name, renewed.Name)
		assert.NotEqual(t, ca.Serial, renewed.Serial)

		// A version
		var again cert.Certificate
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "ca/handler_ca/"+renewed.Serial+"/renew", cert.RenewCertRequest{}, &again))
		assert.NotEqual(t, renewed.Serial, again.Serial)

		status, _ := s.Do(t, http.MethodPost, "ca/missing_ca/renew", cert.RenewCertRequest{})
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("NoRoot", func(t *testing.T) {
		rootless := certtest.IsolatedManager(t, manager.WithPassphrase(1, certtest.Passphrase))
		s := test.NewServer(t, httphandler.RegisterHandlers(rootless, false))
		status, _ := s.Do(t, http.MethodPost, "ca", cert.CreateCertRequest{Name: "orphan_ca"})
		assert.Equal(t, http.StatusServiceUnavailable, status)
	})
}

func Test_Cert(t *testing.T) {
	mgr, _ := certtest.Begin(t)
	s := test.NewServer(t, httphandler.RegisterHandlers(mgr, false))

	var ca cert.Certificate
	require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "ca", cert.CreateCertRequest{Name: "issuing_ca"}, &ca))

	var leaf cert.Certificate
	t.Run("Create", func(t *testing.T) {
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "cert/issuing_ca", cert.CreateCertRequest{Name: "web", SAN: []string{"web.example.test", "10.0.0.1"}, Tags: []string{"web"}}, &leaf))
		assert.Equal(t, "web", leaf.Name)
		assert.False(t, leaf.IsCA)
		assert.Equal(t, ca.CertKey, types.Value(leaf.Signer))
		assert.ElementsMatch(t, []string{"web.example.test", "10.0.0.1"}, leaf.SAN)

		// With a version of the CA
		var api cert.Certificate
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "cert/issuing_ca/"+ca.Serial, cert.CreateCertRequest{Name: "api"}, &api))
		assert.Equal(t, ca.CertKey, types.Value(api.Signer))

		status, _ := s.Do(t, http.MethodPost, "cert/issuing_ca", cert.CreateCertRequest{Name: "web"})
		assert.Equal(t, http.StatusConflict, status, "it exists")
		status, _ = s.Do(t, http.MethodPost, "cert/missing_ca", cert.CreateCertRequest{Name: "other"})
		assert.Equal(t, http.StatusNotFound, status, "no CA")
		status, _ = s.Do(t, http.MethodPost, "cert/issuing_ca", cert.CreateCertRequest{Name: "bad_san", SAN: []string{"not a host"}})
		assert.Equal(t, http.StatusBadRequest, status, "a bad SAN")
	})

	t.Run("Get", func(t *testing.T) {
		var bundle cert.CertBundle
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert/web", nil, &bundle))
		assert.Equal(t, leaf.CertKey, bundle.CertKey)
		assert.Empty(t, bundle.Chain)
		assert.Empty(t, bundle.Key)

		// A version, with its chain: the CA and the root
		var withChain cert.CertBundle
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert/web/"+leaf.Serial+"?chain=true", nil, &withChain))
		require.Len(t, withChain.Chain, 2)
		assert.Equal(t, ca.CertKey, withChain.Chain[0].CertKey)
		assert.Equal(t, cert.RootCertName, withChain.Chain[1].Name)

		status, _ := s.Do(t, http.MethodGet, "cert/missing", nil)
		assert.Equal(t, http.StatusNotFound, status)
	})

	t.Run("PrivateKey", func(t *testing.T) {
		status, header, body := s.Request(t, http.MethodGet, "cert/web/key", nil)
		require.Equal(t, http.StatusOK, status)
		assert.Equal(t, "no-store", header.Get("Cache-Control"))
		var bundle cert.CertBundle
		require.NoError(t, decode(body, &bundle))
		_, err := x509.ParsePKCS8PrivateKey(bundle.Key)
		assert.NoError(t, err, "the key is decrypted")

		// Not a CA's
		// A version, with its chain
		var version cert.CertBundle
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert/web/"+leaf.Serial+"/key?chain=true", nil, &version))
		assert.NotEmpty(t, version.Key)
		assert.Len(t, version.Chain, 2)

		// Not without asking for it, and not a CA's
		var plain cert.CertBundle
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert/web", nil, &plain))
		assert.Empty(t, plain.Key)
		status, _ = s.Do(t, http.MethodGet, "cert/issuing_ca/key", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("List", func(t *testing.T) {
		var list cert.CertList
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert?"+url.Values{"tags": {"web"}}.Encode(), nil, &list))
		require.Equal(t, uint64(1), list.Count)
		assert.Equal(t, leaf.CertKey, list.Body[0].CertKey)

		var cas cert.CertList
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert?is_ca=true", nil, &cas))
		for _, c := range cas.Body {
			assert.True(t, c.IsCA)
			assert.NotEqual(t, cert.RootCertName, c.Name, "the root isn't listed")
		}

		status, _ := s.Do(t, http.MethodGet, "cert?is_ca=maybe", nil)
		assert.Equal(t, http.StatusBadRequest, status)
	})

	t.Run("Renew", func(t *testing.T) {
		var renewed cert.Certificate
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "cert/web/renew", cert.RenewCertRequest{}, &renewed))
		assert.Equal(t, "web", renewed.Name)
		assert.ElementsMatch(t, leaf.SAN, renewed.SAN)

		// The previous version is disabled, and the latest is the renewal
		status, _ := s.Do(t, http.MethodGet, "cert/web/"+leaf.Serial, nil)
		assert.Equal(t, http.StatusConflict, status)
		var latest cert.CertBundle
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "cert/web", nil, &latest))
		assert.Equal(t, renewed.CertKey, latest.CertKey)

		// A version, which is the latest
		var again cert.Certificate
		require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "cert/web/"+renewed.Serial+"/renew", cert.RenewCertRequest{}, &again))
		status, _ = s.Do(t, http.MethodPost, "cert/issuing_ca/renew", cert.RenewCertRequest{})
		assert.Equal(t, http.StatusBadRequest, status, "a CA is renewed as a CA")
	})

	t.Run("Update", func(t *testing.T) {
		var updated cert.Certificate
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "cert/api", cert.CertMeta{Tags: []string{"api"}}, &updated))
		assert.Equal(t, []string{"api"}, updated.Tags)

		disabled := false
		require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "cert/api/"+updated.Serial, cert.CertMeta{Enabled: &disabled}, &updated))
		assert.False(t, types.Value(updated.Enabled))
		status, _ := s.Do(t, http.MethodGet, "cert/api", nil)
		assert.Equal(t, http.StatusConflict, status, "it's disabled")

		status, _ = s.Do(t, http.MethodPatch, "cert/api", cert.CertMeta{})
		assert.Equal(t, http.StatusBadRequest, status, "nothing to update")
		status, _ = s.Do(t, http.MethodPatch, "cert/"+url.PathEscape(cert.RootCertName), cert.CertMeta{Enabled: &disabled})
		assert.Equal(t, http.StatusBadRequest, status, "the root can't be updated")
	})
}

func Test_Subject(t *testing.T) {
	mgr, _ := certtest.Begin(t)
	s := test.NewServer(t, httphandler.RegisterHandlers(mgr, false))

	// Create one, which is listed, got, updated and deleted
	var created cert.Subject
	require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "subject", cert.SubjectMeta{Org: types.Ptr("Handler Org"), Unit: types.Ptr("Web")}, &created))
	assert.NotZero(t, created.ID)
	assert.Equal(t, uint64(0), created.Certs)
	id := strconv.FormatUint(created.ID, 10)

	var list cert.SubjectList
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "subject?limit=100", nil, &list))
	assert.Contains(t, list.Body, created)

	var got cert.Subject
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "subject/"+id, nil, &got))
	assert.Equal(t, created, got)

	var updated cert.Subject
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodPatch, "subject/"+id, cert.SubjectMeta{City: types.Ptr("Leeds")}, &updated))
	assert.Equal(t, "Leeds", types.Value(updated.City))

	status, _ := s.Do(t, http.MethodDelete, "subject/"+id, nil)
	assert.Equal(t, http.StatusNoContent, status)
	status, _ = s.Do(t, http.MethodGet, "subject/"+id, nil)
	assert.Equal(t, http.StatusNotFound, status)

	// One which a certificate uses can't be changed
	var ca cert.Certificate
	require.Equal(t, http.StatusCreated, s.JSON(t, http.MethodPost, "ca", cert.CreateCertRequest{Name: "subject_handler_ca", Subject: &cert.SubjectMeta{Org: types.Ptr("Used By A CA")}}, &ca))
	used := strconv.FormatUint(ca.Subject.ID, 10)
	require.Equal(t, http.StatusOK, s.JSON(t, http.MethodGet, "subject/"+used, nil, &got))
	assert.Equal(t, uint64(1), got.Certs)
	status, _ = s.Do(t, http.MethodPatch, "subject/"+used, cert.SubjectMeta{Org: types.Ptr("Changed")})
	assert.Equal(t, http.StatusConflict, status)
	status, _ = s.Do(t, http.MethodDelete, "subject/"+used, nil)
	assert.Equal(t, http.StatusConflict, status)

	// Bad requests
	status, _ = s.Do(t, http.MethodPost, "subject", cert.SubjectMeta{})
	assert.Equal(t, http.StatusBadRequest, status, "no fields")
	status, _ = s.Do(t, http.MethodGet, "subject/abc", nil)
	assert.Equal(t, http.StatusBadRequest, status, "not an identifier")
	status, _ = s.Do(t, http.MethodPatch, "subject/999999", cert.SubjectMeta{Org: types.Ptr("x")})
	assert.Equal(t, http.StatusNotFound, status)
}

func Test_Spec(t *testing.T) {
	mgr, _ := certtest.Begin(t)
	s := test.NewServer(t, httphandler.RegisterHandlers(mgr, false))

	// Every path is documented, with its tag
	paths := s.Spec().Paths
	require.NotNil(t, paths)
	for path, tag := range map[string]string{
		"/ca":                         "Certificate Authorities",
		"/ca/{name}/renew":            "Certificate Authorities",
		"/ca/{name}/{serial}/renew":   "Certificate Authorities",
		"/cert":                       "Certificates",
		"/cert/{name}":                "Certificates",
		"/cert/{name}/{serial}":       "Certificates",
		"/cert/{name}/key":            "Certificates",
		"/cert/{name}/{serial}/key":   "Certificates",
		"/cert/{name}/renew":          "Certificates",
		"/subject":                    "Subjects",
		"/subject/{id}":               "Subjects",
		"/cert/{name}/{serial}/renew": "Certificates",
	} {
		item, ok := paths.MapOfPathItemValues[test.Prefix+path]
		if assert.True(t, ok, path) {
			for _, op := range []*openapischema.Operation{item.Get, item.Post, item.Patch} {
				if op != nil {
					assert.Equal(t, []string{tag}, op.Tags, path)
				}
			}
		}
	}
}

func Test_Auth(t *testing.T) {
	mgr, _ := certtest.Begin(t)

	// With auth, the operations need a registered security scheme
	router, err := httprouter.NewRouter(context.Background(), http.NewServeMux(), "/api", "", "test", "0.0.0")
	require.NoError(t, err)
	assert.Error(t, httphandler.RegisterHandlers(mgr, true)(router))

	// With one, which grants the scopes in a header, reading a certificate
	// needs cert:read, and its private key cert:key
	mux := http.NewServeMux()
	router, err = httprouter.NewRouter(context.Background(), mux, "/api", "", "test", "0.0.0")
	require.NoError(t, err)
	require.NoError(t, router.RegisterSecurityScheme("bearerAuth", scopeScheme{}))
	require.NoError(t, httphandler.RegisterHandlers(mgr, true)(router))
	server := httptest.NewServer(mux)
	defer server.Close()

	ca, err := mgr.CreateCA(context.Background(), cert.CreateCertRequest{Name: "auth_ca"})
	require.NoError(t, err)
	_, err = mgr.CreateCert(context.Background(), cert.CreateCertRequest{Name: "auth_leaf"}, ca.CertKey)
	require.NoError(t, err)

	get := func(path string, scopes ...string) int {
		req, err := http.NewRequest(http.MethodGet, server.URL+"/api/"+path, nil)
		require.NoError(t, err)
		req.Header.Set("X-Scopes", strings.Join(scopes, ","))
		resp, err := http.DefaultClient.Do(req)
		require.NoError(t, err)
		defer resp.Body.Close()
		return resp.StatusCode
	}
	assert.Equal(t, http.StatusOK, get("cert/auth_leaf", cert.ScopeCertRead))
	assert.Equal(t, http.StatusForbidden, get("cert/auth_leaf"))
	assert.Equal(t, http.StatusForbidden, get("cert/auth_leaf/key", cert.ScopeCertRead), "reading doesn't give the key")
	assert.Equal(t, http.StatusOK, get("cert/auth_leaf/key", cert.ScopeCertKey))
}

// scopeScheme grants the scopes in the X-Scopes header
type scopeScheme struct{}

func (scopeScheme) Spec() openapischema.SecurityScheme {
	return openapischema.SecurityScheme{Type: "http", Scheme: "bearer"}
}

func (scopeScheme) Wrap(handler http.HandlerFunc, scopes []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		granted := strings.Split(r.Header.Get("X-Scopes"), ",")
		for _, scope := range scopes {
			if !slices.Contains(granted, scope) {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		handler(w, r)
	}
}

func decode(body []byte, v any) error {
	return json.Unmarshal(body, v)
}
