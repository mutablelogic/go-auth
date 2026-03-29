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
	"math/big"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	cert "github.com/djthorpe/go-auth/pkg/cert"
	schema "github.com/djthorpe/go-auth/schema/cert"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	certificateStoragePassphraseRequiredReason = "creating certificates requires --storage-passphrase on server"
	certificateStoragePassphraseMismatchReason = "stored certificate private keys cannot be decrypted with current --storage-passphrase"
	certificateStoragePassphraseVersionReason  = "stored certificate private keys require a configured --storage-passphrase version on server"
	rootCertificateRequiredReason              = "root certificate has not been imported on server"
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
		certValue, err := rootCertRow(subjectRow.ID, privateKey, imported)
		if err != nil {
			return err
		}
		version, ciphertext, err := m.passphrase.Encrypt(0, certValue.Key)
		if err != nil {
			return err
		} else {
			certValue.Key = []byte(ciphertext)
			certValue.PV = version
		}

		// Perform the insert
		return conn.Insert(ctx, &certRow, certValue)
	})
	if err != nil {
		return nil, err
	}
	return types.Ptr(certRow), nil
}

func rootCertRow(subjectID uint64, privateKey *rsa.PrivateKey, imported *x509.Certificate) (schema.CertWithPrivateKey, error) {
	if imported == nil {
		return schema.CertWithPrivateKey{}, fmt.Errorf("root certificate is required")
	}

	keyBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		return schema.CertWithPrivateKey{}, err
	}

	return schema.CertWithPrivateKey{
		Cert: schema.Cert{
			CertKey: schema.CertKey{
				Name:   schema.RootCertName,
				Serial: serialText(imported.SerialNumber),
			},
			SubjectID: types.Ptr(subjectID),
			NotBefore: imported.NotBefore,
			NotAfter:  imported.NotAfter,
			IsCA:      imported.IsCA,
			CertMeta: schema.CertMeta{
				Enabled: types.Ptr(true),
			},
			Cert: imported.Raw,
		},
		PV:  0,
		Key: keyBytes,
	}, nil
}

func (m *Manager) getRootCert(ctx context.Context) (*schema.Cert, *cert.Cert, *x509.Certificate, error) {
	var rootRow schema.CertWithPrivateKey

	// Get the root certificate row from the database
	if err := m.Get(ctx, &rootRow, schema.PrivateCertName(schema.RootCertName)); err != nil {
		if errors.Is(err, pg.ErrNotFound) {
			return nil, nil, nil, auth.ErrServiceUnavailable.With(rootCertificateRequiredReason)
		}
		return nil, nil, nil, err
	}
	rootSigner, rootCert, err := m.storedCertSigner(rootRow)
	if err != nil {
		return nil, nil, nil, err
	}
	return &rootRow.Cert, rootSigner, rootCert, nil
}

func (m *Manager) storedCertSigner(certRow schema.CertWithPrivateKey) (*cert.Cert, *x509.Certificate, error) {
	// Decrypt the private key, parse the certificate
	decryptedKey, err := m.decryptStoredPrivateKey(certRow.PV, certRow.Key)
	if err != nil {
		return nil, nil, err
	} else if parsedCert, err := x509.ParseCertificate(certRow.Cert.Cert); err != nil {
		return nil, nil, err
	} else {
		var pemValue bytes.Buffer
		if err := pem.Encode(&pemValue, &pem.Block{Type: "CERTIFICATE", Bytes: certRow.Cert.Cert}); err != nil {
			return nil, nil, err
		} else if err := pem.Encode(&pemValue, &pem.Block{Type: "PRIVATE KEY", Bytes: decryptedKey}); err != nil {
			return nil, nil, err
		} else if signer, err := cert.Read(&pemValue); err != nil {
			return nil, nil, err
		} else {
			signer.Name = certRow.Name
			signer.Subject = certRow.SubjectID
			return signer, parsedCert, nil
		}
	}
}

func certificateStoragePassphraseRequired() error {
	return auth.ErrServiceUnavailable.With(certificateStoragePassphraseRequiredReason)
}

func certificateStorageDecryptError(err error) error {
	switch {
	case err == nil:
		return nil
	case strings.Contains(err.Error(), "passphrase version not found"):
		return auth.ErrServiceUnavailable.With(certificateStoragePassphraseVersionReason)
	case strings.Contains(err.Error(), "message authentication failed"):
		return auth.ErrConflict.With(certificateStoragePassphraseMismatchReason)
	default:
		return err
	}
}

func (m *Manager) decryptStoredPrivateKey(version uint64, ciphertext []byte) ([]byte, error) {
	if m.passphrase == nil {
		return nil, certificateStoragePassphraseRequired()
	}
	decryptedKey, err := m.passphrase.Decrypt(version, string(ciphertext))
	if err != nil {
		return nil, certificateStorageDecryptError(err)
	}
	return decryptedKey, nil
}

func serialText(serial *big.Int) string {
	if serial == nil {
		return ""
	}
	return serial.Text(10)
}
