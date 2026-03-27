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

package crypto_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"testing"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
)

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	assert.Equal(t, 2048, key.N.BitLen())

	pemValue, err := authcrypto.PrivateKeyPEM(key)
	require.NoError(t, err)
	assert.NotEmpty(t, pemValue)

	parsed, err := authcrypto.ParsePrivateKeyPEM(pemValue)
	require.NoError(t, err)
	assert.Equal(t, key.N, parsed.N)
	assert.Equal(t, key.E, parsed.E)
	assert.Equal(t, key.D, parsed.D)
}

func TestPrivateKeyPEMRequiresKey(t *testing.T) {
	_, err := authcrypto.PrivateKeyPEM(nil)
	require.Error(t, err)
}

func TestParsePrivateKeyPEMRejectsInvalidData(t *testing.T) {
	_, err := authcrypto.ParsePrivateKeyPEM("not a pem")
	require.Error(t, err)
}

func TestParsePrivateKeyPEMParsesPKCS1(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	data := x509.MarshalPKCS1PrivateKey(key)
	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: data}))

	parsed, err := authcrypto.ParsePrivateKeyPEM(pemValue)
	require.NoError(t, err)
	assert.Equal(t, key.N, parsed.N)
	assert.Equal(t, key.D, parsed.D)
}

func TestParsePrivateKeyPEMRejectsNonRSA(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	data, err := x509.MarshalPKCS8PrivateKey(ecdsaKey)
	require.NoError(t, err)
	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data}))

	parsed, err := authcrypto.ParsePrivateKeyPEM(pemValue)
	require.Error(t, err)
	assert.Nil(t, parsed)
	assert.Contains(t, err.Error(), "not RSA")
}

func TestParsePrivateKeyPEMRejectsGarbagePEMBody(t *testing.T) {
	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}))
	parsed, err := authcrypto.ParsePrivateKeyPEM(pemValue)
	require.Error(t, err)
	assert.Nil(t, parsed)
}
