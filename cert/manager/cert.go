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
	"math/big"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	schema "github.com/mutablelogic/go-auth/cert/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE TYPES

type certChainSelector cert.CertKey
type certChainList []cert.Certificate

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) ListCerts(ctx context.Context, req cert.CertListRequest) (_ *cert.CertList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.ListCerts", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := cert.CertList{CertListRequest: req}
	if err = m.PoolConn.List(ctx, (*schema.CertList)(&result), schema.CertListRequest(req)); err != nil {
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
func (m *Manager) CreateCert(ctx context.Context, req cert.CreateCertRequest, ca cert.CertKey) (_ *cert.Certificate, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.CreateCert",
		attribute.String("req", req.String()),
		attribute.String("ca", ca.String()),
	)
	defer func() { endSpan(err) }()

	if req.Name == "" {
		return nil, httpresponse.ErrBadRequest.With("name is required")
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

	var caRow cert.Certificate
	if err := m.Get(ctx, (*schema.Certificate)(&caRow), schema.CertKey(ca)); err != nil {
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
	certSubject := cert.MergeSubjectMeta(cert.SubjectMetaFromPKIXName(caCert.Subject), req.Subject)

	validFrom, expires, err := capExpiry(req.Expiry, cert.DefaultCertExpiry, "certificate authority", caCert.NotBefore, caCert.NotAfter)
	if err != nil {
		return nil, err
	}

	leafCert, err := cert.New([]cert.Opt{
		cert.WithCommonName(req.Name),
		cert.WithSubject(certSubject),
		cert.WithSAN(req.SAN...),
		cert.WithRSAKey(0),
		cert.WithValidity(validFrom, expires),
		cert.WithSigner(caSigner),
	}...)
	if err != nil {
		return nil, err
	}

	var certRow cert.Certificate
	if err = m.Tx(ctx, func(conn pg.Conn) error {
		if err := lockName(ctx, conn, req.Name); err != nil {
			return err
		}
		var existing cert.Certificate
		if err := conn.Get(ctx, (*schema.Certificate)(&existing), schema.CertName(req.Name)); err == nil {
			return httpresponse.ErrConflict.Withf("certificate %q already exists", req.Name)
		} else if !errors.Is(err, pg.ErrNotFound) {
			return err
		}

		var subjectRow cert.Subject
		if err := conn.Insert(ctx, (*schema.Subject)(&subjectRow), schema.SubjectMeta(certSubject)); err != nil {
			return err
		}

		certValue := leafCert.SchemaCert()
		certValue.SubjectID = types.Ptr(subjectRow.ID)
		certValue.Signer = &caRow.CertKey
		certValue.Tags = req.Tags

		version, ciphertext, err := m.passphrase.Encrypt(0, certValue.Key)
		if err != nil {
			return err
		}
		certValue.Key = []byte(ciphertext)
		certValue.PV = version

		return conn.Insert(ctx, (*schema.Certificate)(&certRow), schema.CertWithPrivateKey(certValue))
	}); err != nil {
		return nil, err
	}

	// Return the created certificate metadata
	return types.Ptr(certRow), nil
}

func (m *Manager) RenewCert(ctx context.Context, current cert.CertKey, req cert.RenewCertRequest) (_ *cert.Certificate, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.RenewCert",
		attribute.String("current", current.String()),
		attribute.String("req", req.String()),
	)
	defer func() { endSpan(err) }()

	return m.renewCert(ctx, current, req, false)
}

func (m *Manager) UpdateCert(ctx context.Context, key cert.CertKey, meta cert.CertMeta) (_ *cert.Certificate, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.UpdateCert",
		attribute.String("cert", key.String()),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	// The key is trimmed first, so the root can't be updated with spaces
	// around its name
	if key, err = key.Validate(); err != nil {
		return nil, err
	} else if key.Name == cert.RootCertName {
		return nil, httpresponse.ErrBadRequest.With("root certificate cannot be updated")
	}

	var result cert.Certificate
	if err = m.PoolConn.Update(ctx, (*schema.Certificate)(&result), schema.CertKey(key), schema.CertMeta(meta)); err != nil {
		return nil, err
	}

	return types.Ptr(result), nil
}

// GetCert returns the certificate with the name and serial, without its
// private key
func (m *Manager) GetCert(ctx context.Context, key cert.CertKey) (_ *cert.Certificate, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetCert",
		attribute.String("cert", key.String()),
	)
	defer func() { endSpan(err) }()

	var result cert.Certificate
	if err = m.Get(ctx, (*schema.Certificate)(&result), schema.CertKey(key)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// GetLatestCert returns the latest version of the certificate with the
// name, without its private key
func (m *Manager) GetLatestCert(ctx context.Context, name string) (_ *cert.Certificate, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetLatestCert",
		attribute.String("name", name),
	)
	defer func() { endSpan(err) }()

	var result cert.Certificate
	if err = m.Get(ctx, (*schema.Certificate)(&result), schema.CertName(name)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

// GetPrivateKey returns the exact non-CA certificate row with its private key
// decrypted for direct use by callers.
func (m *Manager) GetPrivateKey(ctx context.Context, key cert.CertKey) (_ *cert.CertWithPrivateKey, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetPrivateKey",
		attribute.String("cert", key.String()),
	)
	defer func() { endSpan(err) }()

	// Get the certificate and private key from the database
	result, err := m.getPrivateCert(ctx, key)
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
func (m *Manager) GetCertChain(ctx context.Context, key cert.CertKey) (_ []cert.Certificate, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "certmanager.GetCertChain",
		attribute.String("cert", key.String()),
	)
	defer func() { endSpan(err) }()

	var result certChainList
	if err = m.PoolConn.List(ctx, &result, certChainSelector(key)); err != nil {
		return nil, err
	}
	if len(result) == 0 {
		return nil, pg.ErrNotFound
	}
	return []cert.Certificate(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// lockName serializes creating certificates with the name, until the
// transaction ends, so two can't be created with the same name at once, or
// renewed to the same serial
func lockName(ctx context.Context, conn pg.Conn, name string) error {
	return conn.With("name", name).Exec(ctx, schema.LockName)
}

// capExpiry is when a certificate is valid from, which is now, and until,
// which is after the expiry, or the default expiry when it's not set, but
// never after its signer. Both are worked out from one reading of the clock,
// so the time it takes to create the certificate doesn't change them.
func capExpiry(expiry, defaultExpiry time.Duration, label string, notBefore, notAfter time.Time) (time.Time, time.Time, error) {
	now := time.Now().Truncate(time.Second)
	if now.Before(notBefore) {
		return time.Time{}, time.Time{}, httpresponse.ErrConflict.Withf("%s is not valid yet", label)
	}
	if !notAfter.After(now) {
		return time.Time{}, time.Time{}, httpresponse.ErrConflict.Withf("%s has expired", label)
	}
	if expiry <= 0 {
		expiry = defaultExpiry
	}
	if expires := now.Add(expiry); expires.Before(notAfter) {
		return now, expires, nil
	}
	return now, notAfter, nil
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
	var certificate cert.Certificate
	if err := (*schema.Certificate)(&certificate).Scan(row); err != nil {
		return err
	}
	*list = append(*list, certificate)
	return nil
}

func (m *Manager) getPrivateCert(ctx context.Context, key cert.CertKey) (*cert.CertWithPrivateKey, error) {
	var result cert.CertWithPrivateKey
	if err := m.Get(ctx, (*schema.CertWithPrivateKey)(&result), schema.PrivateCertKey(key)); err != nil {
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) renewCert(ctx context.Context, current cert.CertKey, req cert.RenewCertRequest, expectCA bool) (_ *cert.Certificate, err error) {
	if m.passphrase == nil {
		return nil, certificateStoragePassphraseRequired()
	}
	if _, version := m.passphrase.Get(0); version == 0 {
		return nil, certificateStoragePassphraseRequired()
	}

	var currentRow cert.Certificate
	if err = m.Get(ctx, (*schema.Certificate)(&currentRow), schema.CertKey(current)); err != nil {
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
	subject := cert.MergeSubjectMeta(cert.SubjectMetaFromPKIXName(parsedCurrent.Subject), req.Subject)

	currentLifetime := currentRow.NotAfter.Sub(currentRow.NotBefore)
	validFrom, expires, err := capExpiry(req.Expiry, currentLifetime, signerLabel, signerCert.NotBefore, signerCert.NotAfter)
	if err != nil {
		return nil, err
	}

	nextSerial, err := nextSerial(currentRow.Serial)
	if err != nil {
		return nil, err
	}
	nextKey := cert.CertKey{Name: currentRow.Name, Serial: nextSerial.Text(10)}

	opts := []cert.Opt{
		cert.WithCommonName(currentRow.Name),
		cert.WithSubject(subject),
		cert.WithRSAKey(0),
		cert.WithValidity(validFrom, expires),
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

	var renewedRow cert.Certificate
	if err = m.Tx(ctx, func(conn pg.Conn) error {
		if err := lockName(ctx, conn, nextKey.Name); err != nil {
			return err
		}
		var existing cert.Certificate
		if err := conn.Get(ctx, (*schema.Certificate)(&existing), schema.CertKey(nextKey)); err == nil {
			return httpresponse.ErrConflict.Withf("certificate %q already has serial %q", nextKey.Name, nextKey.Serial)
		} else if !errors.Is(err, pg.ErrNotFound) {
			return err
		}

		// A renewed leaf replaces the current one, which is disabled. A renewed
		// CA doesn't: the current one stays enabled until it's disabled or
		// expires, so its leaves can still be used, and renewed with the new one
		if !expectCA {
			var disabled cert.Certificate
			falseValue := false
			if err := conn.Update(ctx, (*schema.Certificate)(&disabled), schema.CertKey(current), schema.CertMeta(cert.CertMeta{Enabled: &falseValue})); err != nil {
				return err
			}
		}

		var subjectRow cert.Subject
		if err := conn.Insert(ctx, (*schema.Subject)(&subjectRow), schema.SubjectMeta(subject)); err != nil {
			return err
		}

		certValue := renewed.SchemaCert()
		certValue.SubjectID = types.Ptr(subjectRow.ID)
		certValue.Signer = &signerKey
		certValue.Tags = tags

		version, ciphertext, err := m.passphrase.Encrypt(0, certValue.Key)
		if err != nil {
			return err
		}
		certValue.Key = []byte(ciphertext)
		certValue.PV = version

		return conn.Insert(ctx, (*schema.Certificate)(&renewedRow), schema.CertWithPrivateKey(certValue))
	}); err != nil {
		return nil, err
	}

	return types.Ptr(renewedRow), nil
}

func (m *Manager) renewalSigner(ctx context.Context, current cert.Certificate, expectCA bool) (cert.CertKey, *cert.Cert, *x509.Certificate, string, error) {
	signerKey := *current.Signer
	if signerKey.Name == cert.RootCertName {
		if !expectCA {
			return cert.CertKey{}, nil, nil, "", httpresponse.ErrBadRequest.With("root certificate cannot sign leaf certificates")
		}
		rootRow, rootSigner, rootCert, err := m.getRootCert(ctx)
		if err != nil {
			return cert.CertKey{}, nil, nil, "", err
		}
		if !types.Value(rootRow.Enabled) {
			return cert.CertKey{}, nil, nil, "", httpresponse.ErrConflict.With("root certificate is disabled")
		}
		return signerKey, rootSigner, rootCert, "root certificate", nil
	}

	// The latest version of the signer signs the renewal, so a leaf renews
	// with its CA's replacement when the CA has been renewed
	var signerRow cert.Certificate
	if err := m.Get(ctx, (*schema.Certificate)(&signerRow), schema.CertName(signerKey.Name)); err != nil {
		return cert.CertKey{}, nil, nil, "", err
	}
	signerKey = signerRow.CertKey
	if !signerRow.IsCA {
		return cert.CertKey{}, nil, nil, "", httpresponse.ErrBadRequest.With("signer is not a certificate authority")
	}
	if !types.Value(signerRow.Enabled) {
		return cert.CertKey{}, nil, nil, "", httpresponse.ErrConflict.With("certificate authority is disabled")
	}
	privateSigner, err := m.getPrivateCert(ctx, signerKey)
	if err != nil {
		return cert.CertKey{}, nil, nil, "", err
	}
	signer, signerCert, err := m.storedCertSigner(*privateSigner)
	if err != nil {
		return cert.CertKey{}, nil, nil, "", err
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
