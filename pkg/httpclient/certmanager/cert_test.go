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
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/cert"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClientCertMethods(t *testing.T) {
	t.Run("GetCertUsesLatestNamePathAndQueryParameters", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert/leaf_cert", r.URL.Path)
			assert.Equal("true", r.URL.Query().Get("chain"))
			assert.Equal("true", r.URL.Query().Get("private"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertBundle{
				Cert: schema.Cert{
					CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"},
				},
				Chain: []schema.Cert{{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "7"}}, {CertKey: schema.CertKey{Name: schema.RootCertName, Serial: "1"}}},
				Key:   []byte("private-key"),
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.GetCert(context.Background(), schema.CertKey{Name: "leaf_cert"}, true, true)
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("11", response.Serial)
		assert.Len(response.Chain, 2)
		assert.Equal([]byte("private-key"), response.Key)
	})

	t.Run("GetCertUsesExactKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert/leaf_cert/11", r.URL.Path)
			assert.Empty(r.URL.Query().Get("chain"))
			assert.Empty(r.URL.Query().Get("private"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertBundle{
				Cert: schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.GetCert(context.Background(), schema.CertKey{Name: "leaf_cert", Serial: "11"}, false, false)
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("11", response.Serial)
		assert.Empty(response.Chain)
		assert.Empty(response.Key)
	})

	t.Run("UpdateCertUsesLatestNamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPatch, r.Method)
			require.Equal("/cert/leaf_cert", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.CertMeta
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			require.NotNil(req.Enabled)
			assert.False(*req.Enabled)
			assert.Equal([]string{"ops", "prod"}, req.Tags)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}, CertMeta: schema.CertMeta{Enabled: &[]bool{false}[0], Tags: []string{"ops", "prod"}}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		enabled := false
		response, err := client.UpdateCert(context.Background(), schema.CertKey{Name: "leaf_cert"}, schema.CertMeta{Enabled: &enabled, Tags: []string{"ops", "prod"}})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("11", response.Serial)
		require.NotNil(response.Enabled)
		assert.False(*response.Enabled)
		assert.Equal([]string{"ops", "prod"}, response.Tags)
	})

	t.Run("UpdateCertUsesExactKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPatch, r.Method)
			require.Equal("/cert/leaf_cert/11", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.CertMeta
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal([]string{}, req.Tags)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}, CertMeta: schema.CertMeta{Tags: []string{}}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.UpdateCert(context.Background(), schema.CertKey{Name: "leaf_cert", Serial: "11"}, schema.CertMeta{Tags: []string{}})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("11", response.Serial)
		assert.Empty(response.Tags)
	})

	t.Run("CreateCertUsesCAKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/issuer_ca/7", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.CreateCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal("leaf_cert", req.Name)
			assert.Equal(time.Hour, req.Expiry)
			assert.Equal([]string{"api.example.test", "127.0.0.1"}, req.SAN)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{
				CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"},
				Signer:  &schema.CertKey{Name: "issuer_ca", Serial: "7"},
				SAN:     []string{"api.example.test", "127.0.0.1"},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:   "leaf_cert",
			Expiry: time.Hour,
			SAN:    []string{"api.example.test", "127.0.0.1"},
		}, schema.CertKey{Name: "issuer_ca", Serial: "7"})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("11", response.Serial)
		require.NotNil(response.Signer)
		assert.Equal("issuer_ca", response.Signer.Name)
		assert.Equal("7", response.Signer.Serial)
		assert.ElementsMatch([]string{"api.example.test", "127.0.0.1"}, response.SAN)
	})

	t.Run("CreateCertUsesCANamePathWhenSerialOmitted", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/issuer_ca", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.CreateCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal("leaf_cert", req.Name)
			assert.Equal(time.Hour, req.Expiry)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{
				CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"},
				Signer:  &schema.CertKey{Name: "issuer_ca", Serial: "7"},
				SAN:     []string{"api.example.test", "127.0.0.1"},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.CreateCert(context.Background(), schema.CreateCertRequest{
			Name:   "leaf_cert",
			Expiry: time.Hour,
		}, schema.CertKey{Name: "issuer_ca"})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("11", response.Serial)
		require.NotNil(response.Signer)
		assert.Equal("issuer_ca", response.Signer.Name)
		assert.Equal("7", response.Signer.Serial)
		assert.ElementsMatch([]string{"api.example.test", "127.0.0.1"}, response.SAN)
	})

	t.Run("RenewCertUsesLatestNamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/leaf_cert/renew", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(2*time.Hour, req.Expiry)
			require.NotNil(req.Enabled)
			assert.True(*req.Enabled)
			assert.Equal([]string{"renewed"}, req.Tags)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "12"}, CertMeta: schema.CertMeta{Enabled: &[]bool{true}[0], Tags: []string{"renewed"}}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		enabled := true
		response, err := client.RenewCert(context.Background(), schema.CertKey{Name: "leaf_cert"}, schema.RenewCertRequest{Expiry: 2 * time.Hour, Enabled: &enabled, Tags: []string{"renewed"}})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("12", response.Serial)
		require.NotNil(response.Enabled)
		assert.True(*response.Enabled)
		assert.Equal([]string{"renewed"}, response.Tags)
	})

	t.Run("RenewCertUsesExactKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/leaf_cert/11/renew", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			require.NotNil(req.Enabled)
			assert.False(*req.Enabled)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "12"}, CertMeta: schema.CertMeta{Enabled: &[]bool{false}[0]}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		enabled := false
		response, err := client.RenewCert(context.Background(), schema.CertKey{Name: "leaf_cert", Serial: "11"}, schema.RenewCertRequest{Enabled: &enabled})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("leaf_cert", response.Name)
		assert.Equal("12", response.Serial)
		require.NotNil(response.Enabled)
		assert.False(*response.Enabled)
	})

	t.Run("ListCertsUsesQueryParameters", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		limit := uint64(5)
		isCA := true
		enabled := true
		valid := false
		subject := uint64(7)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert", r.URL.Path)
			assert.Equal("1", r.URL.Query().Get("offset"))
			assert.Equal("5", r.URL.Query().Get("limit"))
			assert.Equal("true", r.URL.Query().Get("is_ca"))
			assert.Equal("true", r.URL.Query().Get("enabled"))
			assert.Equal("false", r.URL.Query().Get("valid"))
			assert.Equal("7", r.URL.Query().Get("subject"))
			assert.Equal([]string{"ops", "prod"}, r.URL.Query()["tags"])

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertList{
				CertListRequest: schema.CertListRequest{OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit}, IsCA: &isCA, Enabled: &enabled, Tags: []string{"ops", "prod"}, Valid: &valid, Subject: &subject},
				Count:           1,
				Body:            []schema.Cert{{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "1"}, IsCA: true, SAN: []string{"api.example.test", "127.0.0.1"}}},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.ListCerts(context.Background(), schema.CertListRequest{
			OffsetLimit: pg.OffsetLimit{Offset: 1, Limit: &limit},
			IsCA:        &isCA,
			Enabled:     &enabled,
			Tags:        []string{"ops", "prod"},
			Valid:       &valid,
			Subject:     &subject,
		})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal(uint64(1), response.Count)
		require.Len(response.Body, 1)
		assert.Equal("issuer_ca", response.Body[0].Name)
		assert.Equal("1", response.Body[0].Serial)
		assert.True(response.Body[0].IsCA)
		assert.ElementsMatch([]string{"api.example.test", "127.0.0.1"}, response.Body[0].SAN)
	})

	t.Run("ListCertsReturnsEmptyList", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert", r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertList{Count: 0, Body: []schema.Cert{}}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.ListCerts(context.Background(), schema.CertListRequest{})
		require.NoError(err)
		require.NotNil(response)
		assert.Zero(response.Count)
		assert.Empty(response.Body)
	})
}
