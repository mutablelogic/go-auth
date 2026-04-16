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

package manager

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"testing"
	"time"

	cert "github.com/mutablelogic/go-auth/pkg/cert"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	nooptrace "go.opentelemetry.io/otel/trace/noop"
)

func Test_opt_001(t *testing.T) {
	t.Run("ApplySkipsNil", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(options.apply(nil))
	})

	t.Run("Defaults", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		options.defaults()
		assert.Equal("cert", options.schema)
		require.NotNil(options.passphrase)
		assert.Empty(options.passphrase.Keys())
	})

	t.Run("WithSchema", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.NoError(WithSchema("custom_cert")(options))
		assert.Equal("custom_cert", options.schema)
		assert.EqualError(WithSchema("")(options), "schema name cannot be empty")
	})

	t.Run("WithTracer", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		tracer := nooptrace.NewTracerProvider().Tracer("manager-test")
		assert.NoError(WithTracer(tracer)(options))
		assert.Equal(tracer, options.tracer)
		assert.EqualError(WithTracer(nil)(options), "tracer is required")
	})

	t.Run("WithPassphrase", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		require.NoError(WithPassphrase(3, "secret-3")(options))

		require.NotNil(options.passphrase)
		value, version := options.passphrase.Get(3)
		assert.Equal("secret-3", value)
		assert.Equal(uint64(3), version)
		assert.Equal([]uint64{3}, options.passphrase.Keys())
	})

	t.Run("WithPassphraseRejectsDuplicateVersion", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		require.NoError(WithPassphrase(5, "secret-5")(options))

		err := WithPassphrase(5, "secret-5b")(options)
		require.Error(err)
		assert.EqualError(err, "passphrase version already exists")

		value, version := options.passphrase.Get(5)
		assert.Equal("secret-5", value)
		assert.Equal(uint64(5), version)
	})

	t.Run("WithPassphraseRejectsEmpty", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.EqualError(WithPassphrase(7, "")(options), "passphrase must not be empty")
	})

	t.Run("WithPassphraseRejectsShort", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.EqualError(WithPassphrase(7, "short")(options), "passphrase must be at least 8 characters")
	})

	t.Run("WithPassphraseRejectsZeroVersion", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		assert.EqualError(WithPassphrase(0, "latest")(options), "passphrase version must be greater than zero")
	})

	t.Run("WithRoot", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		root, err := cert.New(
			cert.WithCommonName("Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithRSAKey(2048),
			cert.WithRoot(),
		)
		require.NoError(err)

		var pemValue bytes.Buffer
		require.NoError(root.Write(&pemValue))
		require.NoError(root.WritePrivateKey(&pemValue))

		require.NoError(WithRoot(pemValue.String())(options))

		require.NotNil(options.rootkey)
		require.NotNil(options.rootcert)
		assert.Equal("Root CA", options.rootcert.Subject.CommonName)
	})

	t.Run("ClearRootMaterial", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		root, err := cert.New(
			cert.WithCommonName("Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithRSAKey(2048),
			cert.WithRoot(),
		)
		require.NoError(err)

		var pemValue bytes.Buffer
		require.NoError(root.Write(&pemValue))
		require.NoError(root.WritePrivateKey(&pemValue))
		require.NoError(WithRoot(pemValue.String())(options))

		require.NotNil(options.rootkey)
		require.NotNil(options.rootcert)
		options.clearRootMaterial()
		assert.Nil(options.rootkey)
		assert.Nil(options.rootcert)
	})

	t.Run("WithRootRejectsInvalidPEM", func(t *testing.T) {
		assert := assert.New(t)

		options := new(opt)
		err := WithRoot("not a pem")(options)
		assert.EqualError(err, "invalid PEM block")
	})

	t.Run("WithRootRejectsMissingKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		root, err := cert.New(
			cert.WithCommonName("Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithRSAKey(2048),
			cert.WithRoot(),
		)
		require.NoError(err)

		var pemValue bytes.Buffer
		require.NoError(root.Write(&pemValue))

		err = WithRoot(pemValue.String())(options)
		assert.EqualError(err, "missing certificate or key")
	})

	t.Run("WithRootRejectsNonRSAKey", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		root, err := cert.New(
			cert.WithCommonName("Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithEllipticKey("p256"),
			cert.WithRoot(),
		)
		require.NoError(err)

		var pemValue bytes.Buffer
		require.NoError(root.Write(&pemValue))
		require.NoError(root.WritePrivateKey(&pemValue))

		err = WithRoot(pemValue.String())(options)
		assert.EqualError(err, "private key is not RSA")
	})

	t.Run("ReadPemBlocksRejectsUnsupportedBlockType", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		root, err := cert.New(
			cert.WithCommonName("Root CA"),
			cert.WithOrganization("Example Org", ""),
			cert.WithExpiry(24*time.Hour),
			cert.WithRSAKey(2048),
			cert.WithRoot(),
		)
		require.NoError(err)

		publicKey, err := x509.MarshalPKIXPublicKey(root.PublicKey())
		require.NoError(err)

		pemValue := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicKey})
		_, _, err = readPemBlocks(pemValue)
		assert.EqualError(err, `invalid PEM block type: "PUBLIC KEY"`)
	})

	t.Run("ApplyStopsOnError", func(t *testing.T) {
		assert := assert.New(t)
		require := require.New(t)

		options := new(opt)
		err := options.apply(WithSchema("custom_cert"), WithPassphrase(1, "pass-one"), WithPassphrase(1, "duplicate-pass"))
		require.Error(err)
		assert.EqualError(err, "passphrase version already exists")
		assert.Equal("custom_cert", options.schema)

		value, version := options.passphrase.Get(1)
		assert.Equal("pass-one", value)
		assert.Equal(uint64(1), version)
	})
}
