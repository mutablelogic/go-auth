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

package cert_test

import (
	"bytes"
	"crypto/x509"
	"net"
	"testing"
	"time"

	// Packages
	cert "github.com/djthorpe/go-auth/pkg/cert"
	schema "github.com/djthorpe/go-auth/schema/cert"
	types "github.com/mutablelogic/go-server/pkg/types"
	assert "github.com/stretchr/testify/assert"
)

func Test_Cert_001(t *testing.T) {
	assert := assert.New(t)

	t.Run("1", func(t *testing.T) {
		cert, err := cert.New()
		if assert.Error(err) {
			assert.Nil(cert)
			t.Log(err)
		}
	})

	t.Run("2", func(t *testing.T) {
		cert, err := cert.New(cert.WithRSAKey(0))
		if assert.Error(err) {
			assert.Nil(cert)
			t.Log(err)
		}
	})

	t.Run("3", func(t *testing.T) {
		cert, err := cert.New(
			cert.WithCommonName("leaf.example.test"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
		)
		if assert.NoError(err) {
			assert.NotNil(cert)
			assert.NotNil(cert.PrivateKey())
			assert.NotNil(cert.PublicKey())
		}
	})

}

func Test_Cert_002(t *testing.T) {
	assert := assert.New(t)

	ca, err := cert.New(
		cert.WithCommonName("CA"),
		cert.WithRSAKey(0),
		cert.WithExpiry(time.Hour),
		cert.WithCA(),
	)
	if assert.NoError(err) {
		assert.NotNil(ca)
	}

	t.Run("1", func(t *testing.T) {
		var data bytes.Buffer
		cert, err := cert.New(
			cert.WithCommonName("leaf-one.example.test"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
			cert.WithSigner(ca),
		)
		if assert.NoError(err) {
			assert.NoError(cert.Write(&data))
			t.Log(data.String())
		}
		if assert.NoError(err) {
			assert.NoError(cert.WritePrivateKey(&data))
			t.Log(data.String())
		}
	})

	t.Run("2", func(t *testing.T) {
		var data bytes.Buffer
		var cert1PEM bytes.Buffer
		var cert1KeyPEM bytes.Buffer
		var cert2PEM bytes.Buffer
		var cert2KeyPEM bytes.Buffer
		cert1, err := cert.New(
			cert.WithCommonName("leaf-two.example.test"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
			cert.WithSigner(ca),
		)
		if !assert.NoError(err) {
			t.FailNow()
		}
		assert.NoError(cert1.Write(&cert1PEM))
		assert.NoError(cert1.WritePrivateKey(&cert1KeyPEM))
		// Write the certificate and key
		assert.NoError(cert1.Write(&data))
		assert.NoError(cert1.WritePrivateKey(&data))

		// Read back into another cert
		cert2, err := cert.Read(&data)
		if !assert.NoError(err) {
			t.FailNow()
		}
		assert.NotNil(cert2)
		assert.NoError(cert2.Write(&cert2PEM))
		assert.NoError(cert2.WritePrivateKey(&cert2KeyPEM))
		assert.Equal(cert1PEM.String(), cert2PEM.String())
		assert.Equal(cert1KeyPEM.String(), cert2KeyPEM.String())
	})
}

func Test_Cert_003(t *testing.T) {
	assert := assert.New(t)

	t.Run("RootMarksMetadata", func(t *testing.T) {
		cert, err := cert.New(
			cert.WithCommonName("root.example.test"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
			cert.WithRoot(),
		)
		if !assert.NoError(err) {
			t.FailNow()
		}
		assert.True(cert.IsCA())
		assert.True(cert.IsRoot())
		assert.True(types.Value(cert.CertMeta().Enabled))
	})

	t.Run("RootCannotHaveSigner", func(t *testing.T) {
		root, err := cert.New(
			cert.WithCommonName("root.example.test"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
			cert.WithRoot(),
		)
		if !assert.NoError(err) {
			t.FailNow()
		}

		child, err := cert.New(
			cert.WithCommonName("bad-root.example.test"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
			cert.WithRoot(),
			cert.WithSigner(root),
		)
		if assert.Error(err) {
			assert.Nil(child)
		}
	})
}

func Test_Cert_004(t *testing.T) {
	assert := assert.New(t)

	t.Run("WithSubjectRejectsEmpty", func(t *testing.T) {
		cert, err := cert.New(
			cert.WithCommonName("leaf.example.test"),
			cert.WithSubject(schema.SubjectMeta{}),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
		)
		if assert.Error(err) {
			assert.Nil(cert)
			assert.EqualError(err, "subject is required")
		}
	})

	t.Run("WithSubjectAppliesFields", func(t *testing.T) {
		subject := schema.SubjectMeta{
			Org:           types.Ptr("Example Org"),
			Unit:          types.Ptr("Security"),
			Country:       types.Ptr("US"),
			State:         types.Ptr("California"),
			City:          types.Ptr("San Francisco"),
			StreetAddress: types.Ptr("1 Example Way"),
			PostalCode:    types.Ptr("94105"),
		}

		leaf, err := cert.New(
			cert.WithCommonName("leaf.example.test"),
			cert.WithSubject(subject),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
		)
		if !assert.NoError(err) {
			t.FailNow()
		}

		meta := leaf.SubjectMeta()
		assert.Equal("Example Org", types.Value(meta.Org))
		assert.Equal("Security", types.Value(meta.Unit))
		assert.Equal("US", types.Value(meta.Country))
		assert.Equal("California", types.Value(meta.State))
		assert.Equal("San Francisco", types.Value(meta.City))
		assert.Equal("1 Example Way", types.Value(meta.StreetAddress))
		assert.Equal("94105", types.Value(meta.PostalCode))
	})

	t.Run("WithSANAppliesDNSAndIP", func(t *testing.T) {
		leaf, err := cert.New(
			cert.WithCommonName("leaf.example.test"),
			cert.WithSAN("api.example.test", "*.example.test", "127.0.0.1"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
		)
		if !assert.NoError(err) {
			t.FailNow()
		}

		parsed, err := x509.ParseCertificate(leaf.SchemaCert().Cert.Cert)
		if !assert.NoError(err) {
			t.FailNow()
		}
		assert.ElementsMatch([]string{"api.example.test", "*.example.test"}, parsed.DNSNames)
		if assert.Len(parsed.IPAddresses, 1) {
			assert.True(parsed.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")))
		}
	})

	t.Run("WithSANRejectsCIDR", func(t *testing.T) {
		leaf, err := cert.New(
			cert.WithCommonName("leaf.example.test"),
			cert.WithSAN("10.0.0.0/24"),
			cert.WithRSAKey(0),
			cert.WithExpiry(time.Hour),
		)
		if assert.Error(err) {
			assert.Nil(leaf)
			assert.EqualError(err, `san entry "10.0.0.0/24" is a CIDR range and is not supported for certificates`)
		}
	})
}
