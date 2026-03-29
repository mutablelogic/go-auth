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
	"encoding/json"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/cert"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestGetCertCommand(t *testing.T) {
	t.Run("UsesLatestNamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert/leaf_cert", r.URL.Path)
			assert.Empty(r.URL.RawQuery)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertBundle{
				Cert: schema.Cert{
					CertKey:       schema.CertKey{Name: "leaf_cert", Serial: "11"},
					Subject:       &schema.SubjectRef{Name: types.Ptr("leaf_cert.example.test")},
					SAN:           []string{"leaf_cert.example.test", "127.0.0.1"},
					EffectiveTags: []string{"edge", "prod"},
					CertMeta: schema.CertMeta{
						Enabled: types.Ptr(true),
					},
					NotBefore: time.Date(2026, time.March, 29, 12, 0, 0, 0, time.UTC),
					NotAfter:  time.Date(2026, time.March, 30, 12, 0, 0, 0, time.UTC),
					Ts:        time.Date(2026, time.March, 29, 11, 0, 0, 0, time.UTC),
					Cert:      []byte("leaf-der"),
				},
			}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&GetCertCommand{Name: "leaf_cert", Comments: true}).Run(newFakeCmd(server.URL))
		require.NoError(err)

		assert.Contains(output.String(), "# subject: leaf_cert.example.test")
		assert.Contains(output.String(), "# serial: 11")
		assert.Contains(output.String(), "# san: leaf_cert.example.test, 127.0.0.1")
		assert.Contains(output.String(), "# tags: edge, prod")
		assert.Contains(output.String(), "# enabled: yes")
		assert.Contains(output.String(), "# type: certificate")
		assert.Contains(output.String(), "# signer: -")
		assert.Contains(output.String(), "# not_before: 2026-03-29T12:00:00Z")
		assert.Contains(output.String(), "# not_after: 2026-03-30T12:00:00Z")
		assert.Contains(output.String(), "# created: 2026-03-29T11:00:00Z")

		blocks := parsePEMBlocks(t, output.Bytes())
		require.Len(blocks, 1)
		assert.Equal("CERTIFICATE", blocks[0].Type)
		assert.Equal([]byte("leaf-der"), blocks[0].Bytes)
	})

	t.Run("UsesExactKeyPathWithChainAndPrivate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert/leaf_cert/11", r.URL.Path)
			assert.Equal("true", r.URL.Query().Get("chain"))
			assert.Equal("true", r.URL.Query().Get("private"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertBundle{
				Cert: schema.Cert{
					CertKey:       schema.CertKey{Name: "leaf_cert", Serial: "11"},
					Signer:        &schema.CertKey{Name: "issuer_ca", Serial: "7"},
					Subject:       &schema.SubjectRef{Name: types.Ptr("leaf_cert.example.test")},
					SAN:           []string{"leaf_cert.example.test", "127.0.0.1"},
					EffectiveTags: []string{"leaf", "prod"},
					NotBefore:     time.Date(2026, time.March, 29, 12, 0, 0, 0, time.UTC),
					NotAfter:      time.Date(2026, time.April, 29, 12, 0, 0, 0, time.UTC),
					Ts:            time.Date(2026, time.March, 29, 11, 0, 0, 0, time.UTC),
					CertMeta: schema.CertMeta{
						Enabled: types.Ptr(false),
						Tags:    []string{"leaf"},
					},
					Cert: []byte("leaf-der"),
				},
				Chain: []schema.Cert{
					{
						CertKey:       schema.CertKey{Name: "issuer_ca", Serial: "7"},
						Signer:        &schema.CertKey{Name: "root_ca", Serial: "1"},
						Subject:       &schema.SubjectRef{Name: types.Ptr("issuer_ca.example.test")},
						EffectiveTags: []string{"ca"},
						IsCA:          true,
						NotBefore:     time.Date(2026, time.March, 1, 0, 0, 0, 0, time.UTC),
						NotAfter:      time.Date(2026, time.June, 1, 0, 0, 0, 0, time.UTC),
						Ts:            time.Date(2026, time.March, 1, 1, 0, 0, 0, time.UTC),
						CertMeta: schema.CertMeta{
							Enabled: types.Ptr(true),
						},
						Cert: []byte("issuer-der"),
					},
					{
						CertKey:       schema.CertKey{Name: schema.RootCertName, Serial: "1"},
						Subject:       &schema.SubjectRef{Name: types.Ptr("root_ca.example.test")},
						EffectiveTags: []string{"platform", "root"},
						IsCA:          true,
						NotBefore:     time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
						NotAfter:      time.Date(2036, time.January, 1, 0, 0, 0, 0, time.UTC),
						Ts:            time.Date(2026, time.January, 1, 1, 0, 0, 0, time.UTC),
						CertMeta: schema.CertMeta{
							Enabled: types.Ptr(true),
						},
						Cert: []byte("root-der"),
					},
				},
				Key: []byte("private-der"),
			}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&GetCertCommand{Name: "leaf_cert", Serial: "11", Chain: true, Private: true, Comments: true}).Run(newFakeCmd(server.URL))
		require.NoError(err)

		assert.Contains(output.String(), "# type: private key")
		assert.Contains(output.String(), "# subject: leaf_cert.example.test")
		assert.Contains(output.String(), "# serial: 11")
		assert.Contains(output.String(), "# san: leaf_cert.example.test, 127.0.0.1")
		assert.Contains(output.String(), "# tags: leaf, prod")
		assert.Contains(output.String(), "# enabled: no")
		assert.Contains(output.String(), "# type: certificate")
		assert.Contains(output.String(), "# signer: issuer_ca")
		assert.Contains(output.String(), "# not_before: 2026-03-29T12:00:00Z")
		assert.Contains(output.String(), "# not_after: 2026-04-29T12:00:00Z")
		assert.Contains(output.String(), "# created: 2026-03-29T11:00:00Z")
		assert.Contains(output.String(), "# type: certificate authority")
		assert.Contains(output.String(), "# subject: issuer_ca.example.test")
		assert.Contains(output.String(), "# serial: 7")
		assert.Contains(output.String(), "# tags: ca")
		assert.Contains(output.String(), "# type: root")
		assert.Contains(output.String(), "# subject: root_ca.example.test")
		assert.Contains(output.String(), "# serial: 1")
		assert.Contains(output.String(), "# tags: platform, root")
		assert.Contains(output.String(), "-----END PRIVATE KEY-----\n\n# subject: leaf_cert.example.test")
		assert.Contains(output.String(), "-----END CERTIFICATE-----\n\n# subject: issuer_ca.example.test")

		blocks := parsePEMBlocks(t, output.Bytes())
		require.Len(blocks, 4)
		assert.Equal("PRIVATE KEY", blocks[0].Type)
		assert.Equal([]byte("private-der"), blocks[0].Bytes)
		assert.Equal("CERTIFICATE", blocks[1].Type)
		assert.Equal([]byte("leaf-der"), blocks[1].Bytes)
		assert.Equal([]byte("issuer-der"), blocks[2].Bytes)
		assert.Equal([]byte("root-der"), blocks[3].Bytes)
	})

	t.Run("DebugOutputsJSON", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert/leaf_cert", r.URL.Path)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertBundle{
				Cert: schema.Cert{
					CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"},
					Cert:    []byte("leaf-der"),
				},
			}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		cmdctx := newFakeCmd(server.URL)
		cmdctx.debug = true

		err := (&GetCertCommand{Name: "leaf_cert"}).Run(cmdctx)
		require.NoError(err)

		assert.Contains(output.String(), "\"name\": \"leaf_cert\"")
		assert.Contains(output.String(), "\"cert\": \"bGVhZi1kZXI=\"")
		assert.NotContains(output.String(), "BEGIN CERTIFICATE")
	})

	t.Run("NoCommentsOutputsBarePEM", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodGet, r.Method)
			require.Equal("/cert/leaf_cert/11", r.URL.Path)
			assert.Equal("true", r.URL.Query().Get("chain"))
			assert.Equal("true", r.URL.Query().Get("private"))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.CertBundle{
				Cert: schema.Cert{
					CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"},
					Cert:    []byte("leaf-der"),
				},
				Chain: []schema.Cert{{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "7"}, Cert: []byte("issuer-der")}},
				Key:   []byte("private-der"),
			}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&GetCertCommand{Name: "leaf_cert", Serial: "11", Chain: true, Private: true, Comments: false}).Run(newFakeCmd(server.URL))
		require.NoError(err)

		assert.NotContains(output.String(), "# ")
		assert.Contains(output.String(), "-----END PRIVATE KEY-----\n\n-----BEGIN CERTIFICATE-----")
		assert.Contains(output.String(), "-----END CERTIFICATE-----\n\n-----BEGIN CERTIFICATE-----")
		blocks := parsePEMBlocks(t, output.Bytes())
		require.Len(blocks, 3)
		assert.Equal("PRIVATE KEY", blocks[0].Type)
		assert.Equal("CERTIFICATE", blocks[1].Type)
		assert.Equal("CERTIFICATE", blocks[2].Type)
	})
}

func TestCreateCertCommand(t *testing.T) {
	t.Run("UsesCANamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/issuer_ca", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.CreateCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal("leaf_cert", req.Name)
			assert.Equal(2*time.Hour, req.Expiry)
			assert.Equal([]string{"api.example.test", "127.0.0.1"}, req.SAN)
			assert.Equal([]string{"ops"}, req.Tags)
			require.NotNil(req.Enabled)
			assert.True(*req.Enabled)
			require.NotNil(req.Subject)
			assert.Equal("Example Org", valueOrEmpty(req.Subject.Org))
			assert.Equal("Security", valueOrEmpty(req.Subject.Unit))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}}))
		}))
		defer server.Close()

		cmd := &CreateCertCommand{
			Name:    "leaf_cert",
			CAName:  "issuer_ca",
			Expiry:  2 * time.Hour,
			SAN:     []string{"api.example.test", "127.0.0.1"},
			Enabled: true,
			Tags:    []string{"ops"},
			certSubjectFlags: certSubjectFlags{
				Org:  "Example Org",
				Unit: "Security",
			},
		}

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := cmd.Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
	})

	t.Run("UsesExplicitCAKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/issuer_ca/7", r.URL.Path)

			var req schema.CreateCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal("leaf_cert", req.Name)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}, Signer: &schema.CertKey{Name: "issuer_ca", Serial: "7"}}))
		}))
		defer server.Close()

		cmd := &CreateCertCommand{Name: "leaf_cert", CAName: "issuer_ca", CASerial: "7", Enabled: true}

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := cmd.Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "issuer_ca")
	})
}

func TestUpdateCertCommand(t *testing.T) {
	t.Run("UsesLatestNamePath", func(t *testing.T) {
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
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}, CertMeta: schema.CertMeta{Enabled: types.Ptr(false), Tags: []string{"ops", "prod"}}}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&UpdateCertCommand{Name: "leaf_cert", Disable: true, Tags: []string{"ops", "prod"}}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
	})

	t.Run("UsesExactKeyPathAndClearsTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPatch, r.Method)
			require.Equal("/cert/leaf_cert/11", r.URL.Path)

			var req schema.CertMeta
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal([]string{}, req.Tags)
			assert.Nil(req.Enabled)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}, CertMeta: schema.CertMeta{Tags: []string{}}}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&UpdateCertCommand{Name: "leaf_cert", Serial: "11", ClearTags: true}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
	})

	t.Run("RejectsConflictingEnableDisableFlags", func(t *testing.T) {
		assert := assert.New(t)

		err := (&UpdateCertCommand{Name: "leaf_cert", Enable: true, Disable: true}).Run(newFakeCmd("http://example.test"))
		assert.EqualError(err, "cannot set both enable and disable")
	})

	t.Run("RejectsConflictingTagFlags", func(t *testing.T) {
		assert := assert.New(t)

		err := (&UpdateCertCommand{Name: "leaf_cert", Tags: []string{"ops"}, ClearTags: true}).Run(newFakeCmd("http://example.test"))
		assert.EqualError(err, "cannot set tags and clear-tags together")
	})
}

func TestRenewCertCommand(t *testing.T) {
	t.Run("UsesLatestNamePath", func(t *testing.T) {
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
			require.NotNil(req.Subject)
			assert.Equal("Example Org", valueOrEmpty(req.Subject.Org))
			assert.Equal("Security", valueOrEmpty(req.Subject.Unit))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "12"}}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&RenewCertCommand{
			Name:             "leaf_cert",
			Expiry:           2 * time.Hour,
			Enable:           true,
			Tags:             []string{"renewed"},
			certSubjectFlags: certSubjectFlags{Org: "Example Org", Unit: "Security"},
		}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
	})

	t.Run("UsesExactKeyPathAndClearsTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/leaf_cert/11/renew", r.URL.Path)

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			require.NotNil(req.Enabled)
			assert.False(*req.Enabled)
			assert.Equal([]string{}, req.Tags)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "12"}, CertMeta: schema.CertMeta{Tags: []string{}}}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&RenewCertCommand{Name: "leaf_cert", Serial: "11", Disable: true, ClearTags: true}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
	})

	t.Run("RejectsConflictingEnableDisableFlags", func(t *testing.T) {
		assert := assert.New(t)

		err := (&RenewCertCommand{Name: "leaf_cert", Enable: true, Disable: true}).Run(newFakeCmd("http://example.test"))
		assert.EqualError(err, "cannot set both enable and disable")
	})

	t.Run("RejectsConflictingTagFlags", func(t *testing.T) {
		assert := assert.New(t)

		err := (&RenewCertCommand{Name: "leaf_cert", Tags: []string{"ops"}, ClearTags: true}).Run(newFakeCmd("http://example.test"))
		assert.EqualError(err, "cannot set tags and clear-tags together")
	})
}

func TestRenewCACommand(t *testing.T) {
	t.Run("UsesLatestNamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/ca/issuer_ca/renew", r.URL.Path)
			require.Equal("application/json", r.Header.Get("Content-Type"))

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Equal(3*time.Hour, req.Expiry)
			require.NotNil(req.Enabled)
			assert.True(*req.Enabled)
			assert.Equal([]string{"platform"}, req.Tags)
			require.NotNil(req.Subject)
			assert.Equal("Example Org", valueOrEmpty(req.Subject.Org))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "2"}, IsCA: true}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&RenewCACommand{
			Name:             "issuer_ca",
			Expiry:           3 * time.Hour,
			Enable:           true,
			Tags:             []string{"platform"},
			certSubjectFlags: certSubjectFlags{Org: "Example Org"},
		}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "issuer_ca")
	})

	t.Run("UsesExactKeyPathAndClearsTags", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/ca/issuer_ca/1/renew", r.URL.Path)

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			require.NotNil(req.Enabled)
			assert.False(*req.Enabled)
			assert.Equal([]string{}, req.Tags)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "2"}, IsCA: true, CertMeta: schema.CertMeta{Tags: []string{}}}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&RenewCACommand{Name: "issuer_ca", Serial: "1", Disable: true, ClearTags: true}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "issuer_ca")
	})

	t.Run("RejectsConflictingEnableDisableFlags", func(t *testing.T) {
		assert := assert.New(t)

		err := (&RenewCACommand{Name: "issuer_ca", Enable: true, Disable: true}).Run(newFakeCmd("http://example.test"))
		assert.EqualError(err, "cannot set both enable and disable")
	})

	t.Run("RejectsConflictingTagFlags", func(t *testing.T) {
		assert := assert.New(t)

		err := (&RenewCACommand{Name: "issuer_ca", Tags: []string{"ops"}, ClearTags: true}).Run(newFakeCmd("http://example.test"))
		assert.EqualError(err, "cannot set tags and clear-tags together")
	})
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}

func parsePEMBlocks(t *testing.T, data []byte) []*pem.Block {
	t.Helper()

	blocks := make([]*pem.Block, 0)
	for len(data) > 0 {
		data = bytes.TrimSpace(data)
		if len(data) == 0 {
			break
		}
		block, rest := pem.Decode(data)
		require.NotNil(t, block)
		blocks = append(blocks, block)
		data = rest
	}

	return blocks
}
