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

package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"

	pkcs8 "github.com/youmark/pkcs8"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// GeneratePrivateKey creates a new 2048-bit RSA private key suitable for
// signing tokens.
func GeneratePrivateKey() (*rsa.PrivateKey, error) {
	return rsa.GenerateKey(rand.Reader, 2048)
}

// PrivateKeyPEM encodes an RSA private key as PKCS#8 PEM.
func PrivateKeyPEM(key *rsa.PrivateKey) (string, error) {
	if key == nil {
		return "", fmt.Errorf("private key is required")
	}
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", err
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: data})), nil
}

// ParseCertificatePEM parses a PEM-encoded X.509 certificate.
func ParseCertificatePEM(value []byte) (*x509.Certificate, error) {
	for len(value) > 0 {
		block, rest := pem.Decode(value)
		if block == nil {
			break
		}

		if block.Type == "CERTIFICATE" {
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid certificate PEM")
			}
			return cert, nil
		}

		value = rest
	}

	return nil, fmt.Errorf("invalid certificate PEM")
}

// ParsePrivateKeyPEM parses a PEM-encoded RSA private key in either PKCS#8 or
// PKCS#1 format.
func ParsePrivateKeyPEM(value []byte, passphrase string) (*rsa.PrivateKey, error) {
	for len(value) > 0 {
		block, rest := pem.Decode(value)
		if block == nil {
			break
		}

		switch block.Type {
		case "ENCRYPTED PRIVATE KEY":
			if passphrase == "" {
				return nil, fmt.Errorf("private key passphrase is required")
			}
			key, err := pkcs8.ParsePKCS8PrivateKey(block.Bytes, []byte(passphrase))
			if err != nil {
				return nil, fmt.Errorf("decrypt private key: %w", err)
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not RSA")
			}
			return rsaKey, nil
		case "PRIVATE KEY":
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid PKCS#8 private key PEM")
			}
			rsaKey, ok := key.(*rsa.PrivateKey)
			if !ok {
				return nil, fmt.Errorf("private key is not RSA")
			}
			return rsaKey, nil
		case "RSA PRIVATE KEY":
			if _, ok := block.Headers["DEK-Info"]; ok {
				return nil, fmt.Errorf("legacy PEM encryption is not supported; use PKCS#8 ENCRYPTED PRIVATE KEY")
			}
			key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
			if err != nil {
				return nil, fmt.Errorf("invalid PKCS#1 private key PEM")
			}
			return key, nil
		}

		value = rest
	}

	return nil, fmt.Errorf("invalid RSA private key PEM")
}
