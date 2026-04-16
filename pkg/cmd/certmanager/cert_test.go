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
	schema "github.com/mutablelogic/go-auth/schema/cert"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestGetCertCommand(t *testing.T) {
	t.Run("UsesLatestNamePath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		now := time.Now().UTC().Truncate(time.Second)

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
					NotBefore: now.Add(-1 * time.Hour),
					NotAfter:  now.Add(23 * time.Hour),
					Ts:        now.Add(-2 * time.Hour).Truncate(time.Second),
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
		assert.Contains(output.String(), "# type: certificate, enabled, valid")
		assert.Contains(output.String(), "# signer: -")
		assert.Contains(output.String(), "# not_before: "+now.Add(-1*time.Hour).Format(time.RFC3339))
		assert.Contains(output.String(), "# not_after: "+now.Add(23*time.Hour).Format(time.RFC3339))
		assert.Contains(output.String(), "# created: "+now.Add(-2*time.Hour).Truncate(time.Second).Format(time.RFC3339))

		blocks := parsePEMBlocks(t, output.Bytes())
		require.Len(blocks, 1)
		assert.Equal("CERTIFICATE", blocks[0].Type)
		assert.Equal([]byte("leaf-der"), blocks[0].Bytes)
	})

	t.Run("UsesExactKeyPathWithChainAndPrivate", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)
		now := time.Now().UTC().Truncate(time.Second)

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
					NotBefore:     now.Add(-48 * time.Hour),
					NotAfter:      now.Add(-24 * time.Hour),
					Ts:            now.Add(-72 * time.Hour).Truncate(time.Second),
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
						NotBefore:     now.Add(-7 * 24 * time.Hour),
						NotAfter:      now.Add(7 * 24 * time.Hour),
						Ts:            now.Add(-8 * 24 * time.Hour).Truncate(time.Second),
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
						NotBefore:     now.Add(-365 * 24 * time.Hour),
						NotAfter:      now.Add(365 * 24 * time.Hour),
						Ts:            now.Add(-366 * 24 * time.Hour).Truncate(time.Second),
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

		assert.Contains(output.String(), "# type: private key, disabled, expired")
		assert.Contains(output.String(), "# subject: leaf_cert.example.test")
		assert.Contains(output.String(), "# serial: 11")
		assert.Contains(output.String(), "# san: leaf_cert.example.test, 127.0.0.1")
		assert.Contains(output.String(), "# tags: leaf, prod")
		assert.Contains(output.String(), "# type: certificate, disabled, expired")
		assert.Contains(output.String(), "# signer: issuer_ca")
		assert.Contains(output.String(), "# type: certificate authority, enabled, valid")
		assert.Contains(output.String(), "# subject: issuer_ca.example.test")
		assert.Contains(output.String(), "# serial: 7")
		assert.Contains(output.String(), "# tags: ca")
		assert.Contains(output.String(), "# type: root, enabled, valid")
		assert.Contains(output.String(), "# subject: root_ca.example.test")
		assert.Contains(output.String(), "# serial: 1")
		assert.Contains(output.String(), "# tags: platform, root")
		assert.Contains(output.String(), "-----END PRIVATE KEY-----\n\n# subject: leaf_cert.example.test")
		assert.Contains(output.String(), "-----END CERTIFICATE-----\n\n# subject: issuer_ca.example.test")
		assert.NotContains(output.String(), "# enabled:")

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

func TestPEMTypeLine(t *testing.T) {
	t.Run("CombinesTypeEnabledAndValidity", func(t *testing.T) {
		assert := assert.New(t)

		enabled := true
		cert := schema.Cert{
			NotBefore: time.Now().UTC().Add(-1 * time.Hour),
			NotAfter:  time.Now().UTC().Add(1 * time.Hour),
			CertMeta:  schema.CertMeta{Enabled: &enabled},
		}

		assert.Equal("certificate, enabled, valid", pemTypeLine(cert, "certificate"))
	})

	t.Run("CombinesTypeDisabledAndExpired", func(t *testing.T) {
		assert := assert.New(t)

		enabled := false
		cert := schema.Cert{
			NotBefore: time.Now().UTC().Add(-2 * time.Hour),
			NotAfter:  time.Now().UTC().Add(-1 * time.Hour),
			CertMeta:  schema.CertMeta{Enabled: &enabled},
		}

		assert.Equal("certificate authority, disabled, expired", pemTypeLine(cert, "certificate authority"))
	})

	t.Run("OmitsStatusWhenUnknown", func(t *testing.T) {
		assert := assert.New(t)

		assert.Equal("private key", pemTypeLine(schema.Cert{}, "private key"))
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
			require.NotNil(req.Subject)
			assert.Equal("Example Org", valueOrEmpty(req.Subject.Org))
			assert.Equal("Security", valueOrEmpty(req.Subject.Unit))

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "11"}}))
		}))
		defer server.Close()

		cmd := &CreateCertCommand{
			Name:   "leaf_cert",
			CAName: "issuer_ca",
			Expiry: 2 * time.Hour,
			SAN:    []string{"api.example.test", "127.0.0.1"},
			Tags:   []string{"ops"},
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

		cmd := &CreateCertCommand{Name: "leaf_cert", CAName: "issuer_ca", CASerial: "7"}

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
		assert.EqualError(err, "cannot set --tag and --clear-tags together")
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
			certSubjectFlags: certSubjectFlags{Org: "Example Org", Unit: "Security"},
		}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
	})

	t.Run("UsesExactKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/cert/leaf_cert/11/renew", r.URL.Path)

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Zero(req.Expiry)
			assert.Nil(req.Subject)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "leaf_cert", Serial: "12"}}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&RenewCertCommand{Name: "leaf_cert", Serial: "11"}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "leaf_cert")
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
			certSubjectFlags: certSubjectFlags{Org: "Example Org"},
		}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "issuer_ca")
	})

	t.Run("UsesExactKeyPath", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			require.Equal(http.MethodPost, r.Method)
			require.Equal("/ca/issuer_ca/1/renew", r.URL.Path)

			var req schema.RenewCertRequest
			require.NoError(json.NewDecoder(r.Body).Decode(&req))
			assert.Zero(req.Expiry)
			assert.Nil(req.Subject)

			w.Header().Set("Content-Type", "application/json")
			require.NoError(json.NewEncoder(w).Encode(schema.Cert{CertKey: schema.CertKey{Name: "issuer_ca", Serial: "2"}, IsCA: true}))
		}))
		defer server.Close()

		output := new(bytes.Buffer)
		original := certmanagerOutput
		certmanagerOutput = output
		t.Cleanup(func() { certmanagerOutput = original })

		err := (&RenewCACommand{Name: "issuer_ca", Serial: "1"}).Run(newFakeCmd(server.URL))
		require.NoError(err)
		assert.Contains(output.String(), "issuer_ca")
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
