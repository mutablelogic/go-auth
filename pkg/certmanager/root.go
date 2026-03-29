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
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"

	// Packages
	cert "github.com/djthorpe/go-auth/pkg/cert"
	schema "github.com/djthorpe/go-auth/schema/cert"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// InsertRootCert imports and stores the unique root certificate from a PEM
// bundle containing both the certificate and matching RSA private key.
func (m *Manager) InsertRootCert(ctx context.Context, pemValue string) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.InsertRootCert",
		attribute.String("name", schema.RootCertName),
	)
	defer func() { endSpan(err) }()

	certPEM, keyPEM, err := readPemBlocks([]byte(pemValue))
	if err != nil {
		return nil, err
	}
	keypair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, err
	}
	imported, err := x509.ParseCertificate(keypair.Certificate[0])
	if err != nil {
		return nil, err
	}
	privateKey, ok := keypair.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("private key is not RSA")
	}

	return m.insertRootCert(ctx, imported, privateKey)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (m *Manager) insertRootCert(ctx context.Context, imported *x509.Certificate, privateKey *rsa.PrivateKey) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.insertRootCert",
		attribute.String("name", schema.RootCertName),
	)
	defer func() { endSpan(err) }()

	// Check arguments
	if m.passphrase == nil {
		return nil, fmt.Errorf("root certificate storage passphrase is required")
	}
	if _, version := m.passphrase.Get(0); version == 0 {
		return nil, fmt.Errorf("root certificate storage passphrase is required")
	}
	if privateKey == nil {
		return nil, fmt.Errorf("private key is required")
	}
	if imported == nil {
		return nil, fmt.Errorf("root certificate is required")
	}
	if imported.Subject.String() == "" {
		return nil, fmt.Errorf("subject is required")
	}

	// In a transaction, check if the root certificate already exists, insert the subject, and insert the certificate
	var certRow schema.Cert
	err = m.Tx(ctx, func(conn pg.Conn) error {
		var existing schema.Cert
		if err := conn.Get(ctx, &existing, schema.CertName(schema.RootCertName)); err == nil {
			return httpresponse.ErrConflict.With("root certificate already exists")
		} else if !errors.Is(err, pg.ErrNotFound) {
			return err
		}

		// Insert the subject and get the subject ID
		var subjectRow schema.Subject
		if err := conn.Insert(ctx, &subjectRow, schema.SubjectMetaFromPKIXName(imported.Subject)); err != nil {
			return err
		}

		// Get the certificate metadata, encrypt the private key, and insert the certificate
		meta, err := rootCertMeta(subjectRow.ID, privateKey, imported)
		if err != nil {
			return err
		}
		version, ciphertext, err := m.passphrase.Encrypt(0, meta.Key)
		if err != nil {
			return err
		} else {
			meta.Key = []byte(ciphertext)
			meta.PV = version
		}

		// Perform the insert
		return conn.With("name", schema.RootCertName).Insert(ctx, &certRow, meta)
	})
	if err != nil {
		return nil, err
	}

	return types.Ptr(certRow), nil
}

func rootCertMeta(subjectID uint64, privateKey *rsa.PrivateKey, imported *x509.Certificate) (schema.CertMeta, error) {
	if imported == nil {
		return schema.CertMeta{}, fmt.Errorf("root certificate is required")
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return schema.CertMeta{}, err
	}

	return schema.CertMeta{
		Subject:   types.Ptr(subjectID),
		NotBefore: imported.NotBefore,
		NotAfter:  imported.NotAfter,
		IsCA:      imported.IsCA,
		Enabled:   types.Ptr(true),
		PV:        0,
		Cert:      imported.Raw,
		Key:       keyBytes,
	}, nil
}

func (m *Manager) getRootCert(ctx context.Context) (*schema.Cert, *cert.Cert, *x509.Certificate, error) {
	var rootRow schema.Cert
	var rootCert *x509.Certificate

	// Get the root certificate row from the database
	if err := m.Get(ctx, &rootRow, schema.CertName(schema.RootCertName)); err != nil {
		return nil, nil, nil, err
	}

	// Decrypt the private key, parse the certificate
	decryptedKey, err := m.passphrase.Decrypt(rootRow.PV, string(rootRow.Key))
	if err != nil {
		return nil, nil, nil, err
	} else if cert, err := x509.ParseCertificate(rootRow.Cert); err != nil {
		return nil, nil, nil, err
	} else {
		rootCert = cert
	}

	// Create a PEM bundle of the certificate and decrypted private key, and read it into a cert.Cert signer
	var pemValue bytes.Buffer
	if err := pem.Encode(&pemValue, &pem.Block{Type: "CERTIFICATE", Bytes: rootRow.Cert}); err != nil {
		return nil, nil, nil, err
	} else if err := pem.Encode(&pemValue, &pem.Block{Type: "PRIVATE KEY", Bytes: decryptedKey}); err != nil {
		return nil, nil, nil, err
	} else if rootSigner, err := cert.Read(&pemValue); err != nil {
		return nil, nil, nil, err
	} else {
		rootSigner.Name = rootRow.Name
		rootSigner.Subject = rootRow.Subject
		return &rootRow, rootSigner, rootCert, nil
	}
}
