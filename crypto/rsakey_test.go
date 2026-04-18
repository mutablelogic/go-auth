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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	// Packages
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	pkcs8 "github.com/youmark/pkcs8"
)

func TestParseCertificatePEM(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "example.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, &key.PublicKey, key)
	require.NoError(t, err)

	pemValue := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	parsed, err := authcrypto.ParseCertificatePEM(pemValue)
	require.NoError(t, err)
	assert.Equal(t, "example.test", parsed.Subject.CommonName)
}

func TestParseCertificatePEMFromBundle(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	der, err := x509.CreateCertificate(rand.Reader, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "bundle.example.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			CommonName: "bundle.example.test",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}, &key.PublicKey, key)
	require.NoError(t, err)

	keyPEM, err := authcrypto.PrivateKeyPEM(key)
	require.NoError(t, err)
	bundle := append([]byte(keyPEM), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)

	parsed, err := authcrypto.ParseCertificatePEM(bundle)
	require.NoError(t, err)
	assert.Equal(t, "bundle.example.test", parsed.Subject.CommonName)
}

func TestParseCertificatePEMRejectsInvalidData(t *testing.T) {
	parsed, err := authcrypto.ParseCertificatePEM([]byte("not a pem"))
	require.Error(t, err)
	assert.Nil(t, parsed)
}

func TestPrivateKeyPEMRoundTrip(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)
	assert.Equal(t, 2048, key.N.BitLen())

	pemValue, err := authcrypto.PrivateKeyPEM(key)
	require.NoError(t, err)
	assert.NotEmpty(t, pemValue)

	parsed, err := authcrypto.ParsePrivateKeyPEM([]byte(pemValue), "")
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
	_, err := authcrypto.ParsePrivateKeyPEM([]byte("not a pem"), "")
	require.Error(t, err)
}

func TestParsePrivateKeyPEMParsesPKCS1(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	data := x509.MarshalPKCS1PrivateKey(key)
	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: data}))

	parsed, err := authcrypto.ParsePrivateKeyPEM([]byte(pemValue), "")
	require.NoError(t, err)
	assert.Equal(t, key.N, parsed.N)
	assert.Equal(t, key.D, parsed.D)
}

func TestParsePrivateKeyPEMParsesEncryptedPKCS8(t *testing.T) {
	key, err := authcrypto.GeneratePrivateKey()
	require.NoError(t, err)

	data, err := pkcs8.MarshalPrivateKey(key, []byte("secret"), &pkcs8.Opts{
		Cipher: pkcs8.AES256CBC,
		KDFOpts: pkcs8.PBKDF2Opts{
			SaltSize:       16,
			IterationCount: 10000,
			HMACHash:       crypto.SHA256,
		},
	})
	require.NoError(t, err)

	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: data}))
	parsed, err := authcrypto.ParsePrivateKeyPEM([]byte(pemValue), "secret")
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

	parsed, err := authcrypto.ParsePrivateKeyPEM([]byte(pemValue), "")
	require.Error(t, err)
	assert.Nil(t, parsed)
	assert.Contains(t, err.Error(), "not RSA")
}

func TestParsePrivateKeyPEMRejectsGarbagePEMBody(t *testing.T) {
	pemValue := string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte("garbage")}))
	parsed, err := authcrypto.ParsePrivateKeyPEM([]byte(pemValue), "")
	require.Error(t, err)
	assert.Nil(t, parsed)
}
