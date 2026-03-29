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

	// Packages
	schema "github.com/djthorpe/go-auth/schema/cert"
	pg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClientCertMethods(t *testing.T) {
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
				Body:            []schema.Cert{{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "1"}, IsCA: true}},
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
