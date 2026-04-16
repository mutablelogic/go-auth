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
	schema "github.com/mutablelogic/go-auth/schema/cert"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestClientCAMethods(t *testing.T) {
	t.Run("CreateCAUsesJSONBody", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/ca", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.CreateCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal("issuer_ca", req.Name)
			assert.Equal(time.Hour, req.Expiry)
			assert.Equal([]string{"ops"}, req.Tags)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{
				CertKey: schema.CertKey{Name: "issuer_ca", Serial: "1"},
				IsCA:    true,
				CertMeta: schema.CertMeta{
					Tags: []string{"ops"},
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.CreateCA(context.Background(), schema.CreateCertRequest{Name: "issuer_ca", Expiry: time.Hour, Tags: []string{"ops"}})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("issuer_ca", response.Name)
		assert.Equal("1", response.Serial)
		assert.True(response.IsCA)
		assert.Equal([]string{"ops"}, response.Tags)
	})

	t.Run("RenewCAUsesLatestNamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/ca/issuer_ca/renew", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(time.Hour, req.Expiry)
			assert.Nil(req.Subject)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{
				CertKey: schema.CertKey{Name: "issuer_ca", Serial: "2"},
				IsCA:    true,
				CertMeta: schema.CertMeta{
					Tags: []string{"ops"},
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.RenewCA(context.Background(), schema.CertKey{Name: "issuer_ca"}, schema.RenewCertRequest{Expiry: time.Hour})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("issuer_ca", response.Name)
		assert.Equal("2", response.Serial)
		assert.True(response.IsCA)
		assert.Equal([]string{"ops"}, response.Tags)
	})

	t.Run("RenewCAUsesExactKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/ca/issuer_ca/1/renew", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Zero(req.Expiry)
			assert.Nil(req.Subject)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{
				CertKey: schema.CertKey{Name: "issuer_ca", Serial: "2"},
				IsCA:    true,
				CertMeta: schema.CertMeta{
					Enabled: &[]bool{true}[0],
				},
			}))
		}))
		defer server.Close()

		client, err := New(server.URL)
		require.NoError(err)

		response, err := client.RenewCA(context.Background(), schema.CertKey{Name: "issuer_ca", Serial: "1"}, schema.RenewCertRequest{})
		require.NoError(err)
		require.NotNil(response)
		assert.Equal("issuer_ca", response.Name)
		assert.Equal("2", response.Serial)
		assert.True(response.IsCA)
		require.NotNil(response.Enabled)
		assert.True(*response.Enabled)
	})
}
