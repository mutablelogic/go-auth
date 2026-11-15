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
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/cert/schema"
	authcrypto "github.com/mutablelogic/go-auth/crypto"
	trace "go.opentelemetry.io/otel/trace"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt configures a Manager during construction.
type Opt func(*opt) error

// opt combines all configuration options for Manager.
type opt struct {
	schema     string
	tracer     trace.Tracer
	passphrase *authcrypto.Passphrases
	rootkey    *rsa.PrivateKey
	rootcert   *x509.Certificate
	generate   string
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (o *opt) defaults() {
	o.schema = schema.SchemaName
	o.passphrase = authcrypto.NewPassphrases()
}

func (o *opt) clearRootMaterial() {
	o.rootkey = nil
	o.rootcert = nil
}

func (o *opt) apply(opts ...Opt) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithSchema sets the database schema name to use for all queries. If not set the default schema is used.
func WithSchema(name string) Opt {
	return func(o *opt) error {
		if name == "" {
			return fmt.Errorf("schema name cannot be empty")
		}
		o.schema = name
		return nil
	}
}

// WithTracer sets the OpenTelemetry tracer used for manager spans.
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		o.tracer = tracer
		return nil
	}
}

// WithPassphrase registers an in-memory storage passphrase for a certificate
// passphrase version. Versions are uint64 and passphrases must be non-empty.
func WithPassphrase(version uint64, passphrase string) Opt {
	return func(o *opt) error {
		if o.passphrase == nil {
			o.passphrase = authcrypto.NewPassphrases()
		}
		return o.passphrase.Set(version, passphrase)
	}
}

// WithRoot imports a root certificate and its RSA private key, PEM encoded
// in one string, when the manager is created
func WithRoot(pemValue string) Opt {
	return func(o *opt) error {
		key, cert, err := readRoot([]byte(pemValue))
		if err != nil {
			return err
		}
		o.rootkey = key
		o.rootcert = cert
		return nil
	}
}

// WithGeneratedRoot generates a self-signed root certificate, with the
// common name, when no root is stored and none is imported with WithRoot, so
// certificate authorities can be created without one. A stored root is kept.
func WithGeneratedRoot(commonName string) Opt {
	return func(o *opt) error {
		if commonName = strings.TrimSpace(commonName); commonName == "" {
			return fmt.Errorf("root certificate common name cannot be empty")
		}
		o.generate = commonName
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// readRoot is a root certificate and its RSA private key, from PEM blocks
func readRoot(data []byte) (*rsa.PrivateKey, *x509.Certificate, error) {
	certPEM, keyPEM, err := readPemBlocks(data)
	if err != nil {
		return nil, nil, err
	}
	keypair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		return nil, nil, err
	}
	key, ok := keypair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, nil, fmt.Errorf("private key is not RSA")
	}

	// A root signs itself, and certificate authorities
	if !cert.IsCA || cert.CheckSignatureFrom(cert) != nil {
		return nil, nil, fmt.Errorf("root certificate must be a self-signed certificate authority")
	}
	return key, cert, nil
}

func readPemBlocks(data []byte) ([]byte, []byte, error) {
	var cert, key []byte
	data = bytes.TrimSpace(data)

	for len(data) > 0 {
		var block *pem.Block
		block, data = pem.Decode(data)
		if block == nil {
			return nil, nil, fmt.Errorf("invalid PEM block")
		}

		switch block.Type {
		case "CERTIFICATE":
			if cert == nil {
				cert = pem.EncodeToMemory(block)
			}
		case "PRIVATE KEY", "RSA PRIVATE KEY":
			if key == nil {
				key = pem.EncodeToMemory(block)
			}
		default:
			return nil, nil, fmt.Errorf("invalid PEM block type: %q", block.Type)
		}

		data = bytes.TrimSpace(data)
	}

	if cert == nil || key == nil {
		return nil, nil, fmt.Errorf("missing certificate or key")
	}

	return cert, key, nil
}
