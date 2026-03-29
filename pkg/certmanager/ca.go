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
	"context"
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

// CreateCA creates an intermediate certificate authority signed by the stored
// root certificate. If expiry is zero or negative, DefaultCACertExpiry is used
// and capped to the remaining validity of the root certificate. If subject is
// nil, the root certificate subject attributes are reused, but the common name
// always comes from req.Name.
func (m *Manager) CreateCA(ctx context.Context, req schema.CreateCertRequest) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.CreateCA",
		attribute.String("req", req.String()),
	)
	defer func() { endSpan(err) }()

	// Check arguments
	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if m.passphrase == nil {
		return nil, certificateStoragePassphraseRequired()
	}
	if _, version := m.passphrase.Get(0); version == 0 {
		return nil, certificateStoragePassphraseRequired()
	}

	// Retrieve root certificate and signer
	rootRow, rootSigner, rootCert, err := m.getRootCert(ctx)
	if err != nil {
		return nil, err
	}
	if !types.Value(rootRow.Enabled) {
		return nil, httpresponse.ErrConflict.With("root certificate is disabled")
	}

	// Determine the subject for the CA certificate, defaulting to the root certificate subject if not provided
	caSubject := schema.SubjectMetaFromPKIXName(rootCert.Subject)
	if req.Subject != nil {
		caSubject = *req.Subject
	}

	// Cap the requested expiry to the remaining validity of the root certificate,
	// defaulting to DefaultCACertExpiry if not provided
	expires, err := capExpiry(req.Expiry, schema.DefaultCACertExpiry, "root certificate", rootCert.NotBefore, rootCert.NotAfter)
	if err != nil {
		return nil, err
	}

	// Generate a CA certificate signed by the root certificate
	caCert, err := cert.New([]cert.Opt{
		cert.WithCommonName(req.Name),
		cert.WithSubject(caSubject),
		cert.WithRSAKey(0),
		cert.WithCA(),
		cert.WithExpiry(expires),
		cert.WithSigner(rootSigner),
	}...)
	if err != nil {
		return nil, err
	}

	// Insert the CA certificate and metadata into the database, linked to the root certificate as its signer
	var certRow schema.Cert
	if err = m.Tx(ctx, func(conn pg.Conn) error {
		var existing schema.Cert
		if err := conn.Get(ctx, &existing, schema.CertName(req.Name)); err == nil {
			return httpresponse.ErrConflict.Withf("certificate %q already exists", req.Name)
		} else if !errors.Is(err, pg.ErrNotFound) {
			return err
		}

		// Insert the subject and get the subject ID
		var subjectRow schema.Subject
		if err := conn.Insert(ctx, &subjectRow, caSubject); err != nil {
			return err
		}

		// Get the certificate metadata
		certValue := caCert.SchemaCert()
		certValue.SubjectID = types.Ptr(subjectRow.ID)
		certValue.Signer = &rootRow.CertKey
		certValue.Tags = req.Tags
		if req.Enabled != nil {
			certValue.Enabled = types.Ptr(*req.Enabled)
		}

		// Encrypt the private key and insert the certificate
		version, ciphertext, err := m.passphrase.Encrypt(0, certValue.Key)
		if err != nil {
			return err
		} else {
			certValue.Key = []byte(ciphertext)
			certValue.PV = version
		}

		return conn.Insert(ctx, &certRow, certValue)
	}); err != nil {
		return nil, err
	}
	return types.Ptr(certRow), nil
}

func (m *Manager) RenewCA(ctx context.Context, current schema.CertKey, req schema.RenewCertRequest) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.RenewCA",
		attribute.String("current", current.String()),
		attribute.String("req", req.String()),
	)
	defer func() { endSpan(err) }()

	return m.renewCert(ctx, current, req, true)
}
