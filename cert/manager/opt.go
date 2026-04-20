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
	"crypto/x509"
	"encoding/pem"
	"fmt"

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

// WithRoot imports root certificate and matching RSA private key.
func WithRoot(key *rsa.PrivateKey, cert *x509.Certificate) Opt {
	return func(o *opt) error {
		o.rootkey = key
		o.rootcert = cert
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

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
