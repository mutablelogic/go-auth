package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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

// ParsePrivateKeyPEM parses a PEM-encoded RSA private key in either PKCS#8 or
// PKCS#1 format.
func ParsePrivateKeyPEM(value string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(value))
	if block == nil {
		return nil, fmt.Errorf("invalid private key PEM")
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		rsaKey, ok := key.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("private key is not RSA")
		}
		return rsaKey, nil
	}
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("invalid RSA private key PEM")
}
