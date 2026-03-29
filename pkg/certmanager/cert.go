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
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"

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
// PRIVATE TYPES

type certChainSelector schema.CertKey
type certChainList []schema.Cert

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) ListCerts(ctx context.Context, req schema.CertListRequest) (_ *schema.CertList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.ListCerts", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := schema.CertList{CertListRequest: req}
	if err = m.PoolConn.List(ctx, &result, req); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// CreateCert creates a leaf certificate signed by the explicit non-root CA
// certificate.
// If expiry is zero or negative, DefaultCertExpiry is used and capped to the
// remaining validity of the CA certificate. If subject is nil, the CA
// certificate subject attributes are reused, but the common name always comes
// from req.Name.
func (m *Manager) CreateCert(ctx context.Context, req schema.CreateCertRequest, ca schema.CertKey) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.CreateCert",
		attribute.String("req", req.String()),
		attribute.String("ca", ca.String()),
	)
	defer func() { endSpan(err) }()

	if req.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if err := cert.ValidateSAN(req.SAN...); err != nil {
		return nil, httpresponse.ErrBadRequest.With(err.Error())
	}
	if m.passphrase == nil {
		return nil, certificateStoragePassphraseRequired()
	}
	if _, version := m.passphrase.Get(0); version == 0 {
		return nil, certificateStoragePassphraseRequired()
	}

	var caRow schema.Cert
	if err := m.Get(ctx, &caRow, ca); err != nil {
		return nil, err
	}
	if caRow.IsRoot() {
		return nil, httpresponse.ErrBadRequest.With("root certificate cannot sign leaf certificates")
	}
	if !caRow.IsCA {
		return nil, httpresponse.ErrBadRequest.With("signer is not a certificate authority")
	}
	if !types.Value(caRow.Enabled) {
		return nil, httpresponse.ErrConflict.With("certificate authority is disabled")
	}

	privateCA, err := m.getPrivateCert(ctx, caRow.CertKey)
	if err != nil {
		return nil, err
	}
	caSigner, caCert, err := m.storedCertSigner(*privateCA)
	if err != nil {
		return nil, err
	}

	// Determine the subject for the leaf certificate by overlaying any explicit
	// request fields onto the signing CA subject. Empty string values clear
	// inherited fields.
	certSubject := schema.MergeSubjectMeta(schema.SubjectMetaFromPKIXName(caCert.Subject), req.Subject)

	expires, err := capExpiry(req.Expiry, schema.DefaultCertExpiry, "certificate authority", caCert.NotBefore, caCert.NotAfter)
	if err != nil {
		return nil, err
	}

	leafCert, err := cert.New([]cert.Opt{
		cert.WithCommonName(req.Name),
		cert.WithSubject(certSubject),
		cert.WithSAN(req.SAN...),
		cert.WithRSAKey(0),
		cert.WithExpiry(expires),
		cert.WithSigner(caSigner),
	}...)
	if err != nil {
		return nil, err
	}

	var certRow schema.Cert
	if err = m.Tx(ctx, func(conn pg.Conn) error {
		var existing schema.Cert
		if err := conn.Get(ctx, &existing, schema.CertName(req.Name)); err == nil {
			return httpresponse.ErrConflict.Withf("certificate %q already exists", req.Name)
		} else if !errors.Is(err, pg.ErrNotFound) {
			return err
		}

		var subjectRow schema.Subject
		if err := conn.Insert(ctx, &subjectRow, certSubject); err != nil {
			return err
		}

		certValue := leafCert.SchemaCert()
		certValue.SubjectID = types.Ptr(subjectRow.ID)
		certValue.Signer = &caRow.CertKey
		certValue.Tags = req.Tags
		if req.Enabled != nil {
			certValue.Enabled = types.Ptr(*req.Enabled)
		}

		version, ciphertext, err := m.passphrase.Encrypt(0, certValue.Key)
		if err != nil {
			return err
		}
		certValue.Key = []byte(ciphertext)
		certValue.PV = version

		return conn.Insert(ctx, &certRow, certValue)
	}); err != nil {
		return nil, err
	}

	// Return the created certificate metadata
	return types.Ptr(certRow), nil
}

func (m *Manager) RenewCert(ctx context.Context, current schema.CertKey, req schema.RenewCertRequest) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.RenewCert",
		attribute.String("current", current.String()),
		attribute.String("req", req.String()),
	)
	defer func() { endSpan(err) }()

	return m.renewCert(ctx, current, req, false)
}

func (m *Manager) UpdateCert(ctx context.Context, cert schema.CertKey, meta schema.CertMeta) (_ *schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.UpdateCert",
		attribute.String("cert", cert.String()),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	if cert.Name == schema.RootCertName {
		return nil, httpresponse.ErrBadRequest.With("root certificate cannot be updated")
	}

	var result schema.Cert
	if err = m.PoolConn.Update(ctx, &result, cert, meta); err != nil {
		return nil, err
	}

	return types.Ptr(result), nil
}

// GetPrivateKey returns the exact non-CA certificate row with its private key
// decrypted for direct use by callers.
func (m *Manager) GetPrivateKey(ctx context.Context, cert schema.CertKey) (_ *schema.CertWithPrivateKey, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetPrivateKey",
		attribute.String("cert", cert.String()),
	)
	defer func() { endSpan(err) }()

	// Get the certificate and private key from the database
	result, err := m.getPrivateCert(ctx, cert)
	if err != nil {
		return nil, err
	}
	if result.IsRoot() {
		return nil, httpresponse.ErrBadRequest.With("root certificate private key cannot be retrieved")
	}
	if result.IsCA {
		return nil, httpresponse.ErrBadRequest.With("certificate authority private key cannot be retrieved")
	}

	// Decrypt the private key and return the result with the PV set to 0 since the key is now decrypted
	if decryptedKey, err := m.decryptStoredPrivateKey(result.PV, result.Key); err != nil {
		return nil, err
	} else {
		result.Key = decryptedKey
		result.PV = 0
	}

	// Return the certificate with decrypted key
	return result, nil
}

// GetCertChain returns the certificate row identified by key together with its
// issuer chain. PEM encoding is handled separately at the HTTP layer.
func (m *Manager) GetCertChain(ctx context.Context, cert schema.CertKey) (_ []schema.Cert, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetCertChain",
		attribute.String("cert", cert.String()),
	)
	defer func() { endSpan(err) }()

	var result certChainList
	if err = m.PoolConn.List(ctx, &result, certChainSelector(cert)); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, pg.ErrNotFound
	}
	return []schema.Cert(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func capExpiry(expiry, defaultExpiry time.Duration, label string, notBefore, notAfter time.Time) (time.Duration, error) {
	now := time.Now().Truncate(time.Second)
	if now.Before(notBefore) {
		return 0, fmt.Errorf("%s is not valid yet", label)
	}
	remaining := notAfter.Sub(now).Truncate(time.Second)
	if remaining <= 0 {
		return 0, fmt.Errorf("%s has expired", label)
	}
	if expiry <= 0 {
		expiry = defaultExpiry
	}
	if expiry > remaining {
		return remaining, nil
	}
	return expiry, nil
}

func (selector certChainSelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if _, err := schema.CertKey(selector).Select(bind, pg.Get); err != nil {
		return "", err
	}
	switch op {
	case pg.List:
		return bind.Query("cert.chain"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("certChainSelector: operation %q is not supported", op)
	}
}

func (list *certChainList) Scan(row pg.Row) error {
	var cert schema.Cert
	if err := cert.Scan(row); err != nil {
		return err
	}
	*list = append(*list, cert)
	return nil
}

func (m *Manager) getPrivateCert(ctx context.Context, cert schema.CertKey) (*schema.CertWithPrivateKey, error) {
	var result schema.CertWithPrivateKey
	if err := m.Get(ctx, &result, schema.PrivateCertKey(cert)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) renewCert(ctx context.Context, current schema.CertKey, req schema.RenewCertRequest, expectCA bool) (_ *schema.Cert, err error) {
	if m.passphrase == nil {
		return nil, certificateStoragePassphraseRequired()
	}
	if _, version := m.passphrase.Get(0); version == 0 {
		return nil, certificateStoragePassphraseRequired()
	}

	var currentRow schema.Cert
	if err = m.Get(ctx, &currentRow, current); err != nil {
		return nil, err
	}
	if currentRow.IsRoot() {
		return nil, httpresponse.ErrBadRequest.With("root certificate cannot be renewed")
	}
	if expectCA && !currentRow.IsCA {
		return nil, httpresponse.ErrBadRequest.With("certificate is not a certificate authority")
	}
	if !expectCA && currentRow.IsCA {
		return nil, httpresponse.ErrBadRequest.With("certificate is not a leaf certificate")
	}
	if !types.Value(currentRow.Enabled) {
		if currentRow.IsCA {
			return nil, httpresponse.ErrConflict.With("certificate authority is disabled")
		}
		return nil, httpresponse.ErrConflict.With("certificate is disabled")
	}
	if currentRow.Signer == nil {
		return nil, httpresponse.ErrBadRequest.With("non-root certificate must have a signer")
	}

	parsedCurrent, err := x509.ParseCertificate(currentRow.Cert)
	if err != nil {
		return nil, err
	}

	signerKey, signer, signerCert, signerLabel, err := m.renewalSigner(ctx, currentRow, expectCA)
	if err != nil {
		return nil, err
	}

	// Determine the renewed subject by overlaying any explicit request fields
	// onto the current certificate subject. Empty string values clear inherited
	// fields while nil preserves them.
	subject := schema.MergeSubjectMeta(schema.SubjectMetaFromPKIXName(parsedCurrent.Subject), req.Subject)

	currentLifetime := currentRow.NotAfter.Sub(currentRow.NotBefore)
	expires, err := capExpiry(req.Expiry, currentLifetime, signerLabel, signerCert.NotBefore, signerCert.NotAfter)
	if err != nil {
		return nil, err
	}

	nextSerial, err := nextSerial(currentRow.Serial)
	if err != nil {
		return nil, err
	}
	nextKey := schema.CertKey{Name: currentRow.Name, Serial: nextSerial.Text(10)}

	opts := []cert.Opt{
		cert.WithCommonName(currentRow.Name),
		cert.WithSubject(subject),
		cert.WithRSAKey(0),
		cert.WithExpiry(expires),
		cert.WithSerial(nextSerial),
		cert.WithSigner(signer),
	}
	if san := certSAN(parsedCurrent); len(san) > 0 {
		opts = append(opts, cert.WithSAN(san...))
	}
	if expectCA {
		opts = append(opts, cert.WithCA())
	}
	renewed, err := cert.New(opts...)
	if err != nil {
		return nil, err
	}

	tags := append([]string(nil), currentRow.Tags...)
	if req.Tags != nil {
		tags = req.Tags
	}
	enabled := types.Value(currentRow.Enabled)
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	var renewedRow schema.Cert
	if err = m.Tx(ctx, func(conn pg.Conn) error {
		var existing schema.Cert
		if err := conn.Get(ctx, &existing, nextKey); err == nil {
			return httpresponse.ErrConflict.Withf("certificate %q already has serial %q", nextKey.Name, nextKey.Serial)
		} else if !errors.Is(err, pg.ErrNotFound) {
			return err
		}

		var disabled schema.Cert
		falseValue := false
		if err := conn.Update(ctx, &disabled, current, schema.CertMeta{Enabled: &falseValue}); err != nil {
			return err
		}

		var subjectRow schema.Subject
		if err := conn.Insert(ctx, &subjectRow, subject); err != nil {
			return err
		}

		certValue := renewed.SchemaCert()
		certValue.SubjectID = types.Ptr(subjectRow.ID)
		certValue.Signer = &signerKey
		certValue.Tags = tags
		certValue.Enabled = types.Ptr(enabled)

		version, ciphertext, err := m.passphrase.Encrypt(0, certValue.Key)
		if err != nil {
			return err
		}
		certValue.Key = []byte(ciphertext)
		certValue.PV = version

		return conn.Insert(ctx, &renewedRow, certValue)
	}); err != nil {
		return nil, err
	}

	return types.Ptr(renewedRow), nil
}

func (m *Manager) renewalSigner(ctx context.Context, current schema.Cert, expectCA bool) (schema.CertKey, *cert.Cert, *x509.Certificate, string, error) {
	signerKey := *current.Signer
	if signerKey.Name == schema.RootCertName {
		if !expectCA {
			return schema.CertKey{}, nil, nil, "", httpresponse.ErrBadRequest.With("root certificate cannot sign leaf certificates")
		}
		rootRow, rootSigner, rootCert, err := m.getRootCert(ctx)
		if err != nil {
			return schema.CertKey{}, nil, nil, "", err
		}
		if !types.Value(rootRow.Enabled) {
			return schema.CertKey{}, nil, nil, "", httpresponse.ErrConflict.With("root certificate is disabled")
		}
		return signerKey, rootSigner, rootCert, "root certificate", nil
	}

	var signerRow schema.Cert
	if err := m.Get(ctx, &signerRow, signerKey); err != nil {
		return schema.CertKey{}, nil, nil, "", err
	}
	if !signerRow.IsCA {
		return schema.CertKey{}, nil, nil, "", httpresponse.ErrBadRequest.With("signer is not a certificate authority")
	}
	if !types.Value(signerRow.Enabled) {
		return schema.CertKey{}, nil, nil, "", httpresponse.ErrConflict.With("certificate authority is disabled")
	}
	privateSigner, err := m.getPrivateCert(ctx, signerKey)
	if err != nil {
		return schema.CertKey{}, nil, nil, "", err
	}
	signer, signerCert, err := m.storedCertSigner(*privateSigner)
	if err != nil {
		return schema.CertKey{}, nil, nil, "", err
	}
	return signerKey, signer, signerCert, "certificate authority", nil
}

func nextSerial(serial string) (*big.Int, error) {
	value, ok := new(big.Int).SetString(serial, 10)
	if !ok || value.Sign() < 0 {
		return nil, httpresponse.ErrBadRequest.With("serial is invalid")
	}
	return value.Add(value, big.NewInt(1)), nil
}

func certSAN(parsed *x509.Certificate) []string {
	if parsed == nil {
		return nil
	}
	san := append([]string(nil), parsed.DNSNames...)
	for _, ip := range parsed.IPAddresses {
		san = append(san, ip.String())
	}
	if len(san) == 0 {
		return nil
	}
	return san
}
