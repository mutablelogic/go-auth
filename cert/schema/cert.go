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

package schema

import (
	"crypto/x509"
	"strings"
	"time"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// CertName selects the latest certificate with a name
type CertName string

// PrivateCertName selects the latest certificate with a name, with its
// private key
type PrivateCertName string

// CertKey selects a certificate by its name and serial
type CertKey cert.CertKey

// PrivateCertKey selects a certificate by its name and serial, with its
// private key
type PrivateCertKey cert.CertKey

// CertMeta updates a certificate's metadata
type CertMeta cert.CertMeta

// CertListRequest lists certificates
type CertListRequest cert.CertListRequest

// Certificate reads a certificate
type Certificate cert.Certificate

// CertWithPrivateKey inserts a certificate with its private key, and reads
// one
type CertWithPrivateKey cert.CertWithPrivateKey

// CertList reads a list of certificates
type CertList cert.CertList

////////////////////////////////////////////////////////////////////////////////
// SELECTOR

func (c CertName) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if name, err := cert.ValidateCertName(string(c)); err != nil {
		return "", err
	} else {
		bind.Set("name", name)
	}

	switch op {
	case pg.Get:
		return bind.Query("cert.select_latest"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("CertName: operation %q is not supported", op)
	}
}

func (c PrivateCertName) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if name, err := cert.ValidateCertName(string(c)); err != nil {
		return "", err
	} else {
		bind.Set("name", name)
	}

	switch op {
	case pg.Get:
		return bind.Query("cert.select_latest_private"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("PrivateCertName: operation %q is not supported", op)
	}
}

func (c CertKey) Select(bind *pg.Bind, op pg.Op) (string, error) {
	key, err := cert.CertKey(c).Validate()
	if err != nil {
		return "", err
	}
	bind.Set("name", key.Name)
	bind.Set("serial", key.Serial)

	switch op {
	case pg.Get:
		return bind.Query("cert.select"), nil
	case pg.Update:
		return bind.Query("cert.update"), nil
	case pg.Delete:
		return bind.Query("cert.delete"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("CertKey: operation %q is not supported", op)
	}
}

func (c PrivateCertKey) Select(bind *pg.Bind, op pg.Op) (string, error) {
	key, err := cert.CertKey(c).Validate()
	if err != nil {
		return "", err
	}
	bind.Set("name", key.Name)
	bind.Set("serial", key.Serial)

	switch op {
	case pg.Get:
		return bind.Query("cert.select_private"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("PrivateCertKey: operation %q is not supported", op)
	}
}

func (c CertListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Del("where")
	bind.Append("where", `cert_row."name" <> `+bind.Set("root_name", cert.RootCertName))

	if c.IsCA != nil {
		bind.Append("where", `cert_row."is_ca" = `+bind.Set("is_ca", *c.IsCA))
	}
	if c.Enabled != nil {
		bind.Append("where", `COALESCE(effective.effective_enabled, cert_row."enabled") = `+bind.Set("enabled", *c.Enabled))
	}
	if tags, err := cert.NormalizeTags(c.Tags); err != nil {
		return "", err
	} else if len(tags) > 0 {
		bind.Append("where", `COALESCE(effective.effective_tags, '{}'::TEXT[]) @> `+bind.Set("tags", tags))
	}
	if c.Valid != nil {
		if types.Value(c.Valid) == true {
			bind.Append("where", `cert_row."not_before" <= CURRENT_TIMESTAMP AND cert_row."not_after" > CURRENT_TIMESTAMP`)
		} else {
			bind.Append("where", `(cert_row."not_before" > CURRENT_TIMESTAMP OR cert_row."not_after" <= CURRENT_TIMESTAMP)`)
		}
	}
	if c.Subject != nil {
		if types.Value(c.Subject) == 0 {
			return "", httpresponse.ErrBadRequest.With("subject is invalid")
		}
		bind.Append("where", `cert_row."subject" = `+bind.Set("subject", *c.Subject))
	}

	if where := bind.Join("where", " AND "); where == "" {
		bind.Set("where", "")
	} else {
		bind.Set("where", "WHERE "+where)
	}
	bind.Set("orderby", `ORDER BY cert_row."name" ASC, cert_row."serial"::NUMERIC DESC, cert_row."id" DESC`)
	offsetlimit := pg.OffsetLimit(c.OffsetLimit)
	offsetlimit.Bind(bind, CertListLimit)

	switch op {
	case pg.List:
		return bind.Query("cert.list"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("CertListRequest: operation %q is not supported", op)
	}
}

////////////////////////////////////////////////////////////////////////////////
// READER

func (c *Certificate) Scan(row pg.Row) error {
	return scanCert(row, (*cert.Certificate)(c), nil, nil)
}

func (c *CertWithPrivateKey) Scan(row pg.Row) error {
	return scanCert(row, &c.Certificate, &c.Key, &c.PV)
}

func scanCert(row pg.Row, c *cert.Certificate, key *[]byte, pv *uint64) error {
	var enabled bool
	var signerName, signerSerial *string
	var subjectOrg, subjectUnit, subjectCountry, subjectCity, subjectState, subjectStreetAddress, subjectPostalCode *string
	var subjectTs *time.Time

	if key != nil && pv != nil {
		if err := row.Scan(&c.ID, &c.Name, &c.Serial, &c.SubjectID, &subjectOrg, &subjectUnit, &subjectCountry, &subjectCity, &subjectState, &subjectStreetAddress, &subjectPostalCode, &subjectTs, &signerName, &signerSerial, &c.Cert, key, &c.NotBefore, &c.NotAfter, &c.IsCA, &enabled, &c.Tags, &c.EffectiveTags, pv, &c.Ts); err != nil {
			return err
		}
	} else {
		if err := row.Scan(&c.ID, &c.Name, &c.Serial, &c.SubjectID, &subjectOrg, &subjectUnit, &subjectCountry, &subjectCity, &subjectState, &subjectStreetAddress, &subjectPostalCode, &subjectTs, &signerName, &signerSerial, &c.Cert, &c.NotBefore, &c.NotAfter, &c.IsCA, &enabled, &c.Tags, &c.EffectiveTags, &c.Ts); err != nil {
			return err
		}
	}
	var parsedCert *x509.Certificate
	if value, err := x509.ParseCertificate(c.Cert); err == nil {
		parsedCert = value
		san := append([]string(nil), value.DNSNames...)
		for _, ip := range value.IPAddresses {
			san = append(san, ip.String())
		}
		if len(san) > 0 {
			c.SAN = san
		} else {
			c.SAN = nil
		}
	} else {
		c.SAN = nil
	}
	if c.SubjectID != nil {
		meta := cert.SubjectMeta{
			Org:           subjectOrg,
			Unit:          subjectUnit,
			Country:       subjectCountry,
			City:          subjectCity,
			State:         subjectState,
			StreetAddress: subjectStreetAddress,
			PostalCode:    subjectPostalCode,
		}
		var commonName *string
		if parsedCert != nil {
			if value := strings.TrimSpace(parsedCert.Subject.CommonName); value != "" {
				commonName = types.Ptr(value)
			}
		}
		c.Subject = types.Ptr(cert.SubjectRefFromMeta(types.Value(c.SubjectID), meta, types.Value(subjectTs), commonName))
	} else {
		c.Subject = nil
	}
	if signerName != nil || signerSerial != nil {
		c.Signer = &cert.CertKey{Name: strings.TrimSpace(types.Value(signerName)), Serial: strings.TrimSpace(types.Value(signerSerial))}
	} else {
		c.Signer = nil
	}
	c.Enabled = types.Ptr(enabled)
	return nil
}

func (c *CertList) Scan(row pg.Row) error {
	var certificate cert.Certificate
	if err := (*Certificate)(&certificate).Scan(row); err != nil {
		return err
	}
	c.Body = append(c.Body, certificate)
	return nil
}

func (c *CertList) ScanCount(row pg.Row) error {
	if err := row.Scan(&c.Count); err != nil {
		return err
	}
	offsetlimit := pg.OffsetLimit(c.OffsetLimit)
	offsetlimit.Clamp(c.Count)
	c.OffsetLimit = cert.OffsetLimit(offsetlimit)
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// WRITER

func (c CertWithPrivateKey) Insert(bind *pg.Bind) (string, error) {
	key, err := c.CertKey.Validate()
	if err != nil {
		return "", err
	}
	bind.Set("name", key.Name)
	bind.Set("serial", key.Serial)

	// Signer
	if c.Signer != nil {
		signer, err := c.Signer.Validate()
		if err != nil {
			return "", err
		}
		bind.Set("issuer_name", signer.Name)
		bind.Set("issuer_serial", signer.Serial)
	} else {
		bind.Set("issuer_name", nil)
		bind.Set("issuer_serial", nil)
	}

	// Subject
	if subject := types.Value(c.SubjectID); subject == 0 {
		return "", httpresponse.ErrBadRequest.With("subject is missing")
	} else {
		bind.Set("subject", subject)
	}

	// NotBefore
	if c.NotBefore.IsZero() {
		return "", httpresponse.ErrBadRequest.With("not_before is missing")
	} else {
		bind.Set("not_before", c.NotBefore)
	}

	// NotAfter
	if c.NotAfter.IsZero() {
		return "", httpresponse.ErrBadRequest.With("not_after is missing")
	} else if c.NotAfter.Before(c.NotBefore) {
		return "", httpresponse.ErrBadRequest.With("not_after is before not_before")
	} else {
		bind.Set("not_after", c.NotAfter)
	}

	// Set cert and key
	bind.Set("cert", c.Certificate.Cert)
	bind.Set("key", c.Key)

	// IsCA
	bind.Set("is_ca", c.IsCA)
	if c.Enabled == nil {
		bind.Set("enabled", true)
	} else {
		bind.Set("enabled", *c.Enabled)
	}
	if tags, err := cert.NormalizeTags(c.Tags); err != nil {
		return "", err
	} else {
		bind.Set("tags", tags)
	}
	bind.Set("pv", c.PV)
	if key.Name == cert.RootCertName {
		if !c.IsCA {
			return "", httpresponse.ErrBadRequest.With("root certificate must be a certificate authority")
		}
		if c.Signer != nil {
			return "", httpresponse.ErrBadRequest.With("root certificate cannot have a signer")
		}
	} else if c.Signer == nil {
		return "", httpresponse.ErrBadRequest.With("non-root certificate must have a signer")
	}

	// Return insert or replace
	return bind.Query("cert.insert"), nil
}

func (c CertMeta) Insert(bind *pg.Bind) (string, error) {
	_ = bind
	return "", httpresponse.ErrNotImplemented.With("cert meta insert is not supported")
}

func (c CertMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")

	if c.Enabled != nil {
		bind.Append("patch", `"enabled" = `+bind.Set("enabled", *c.Enabled))
	}
	if c.Tags != nil {
		tags, err := cert.NormalizeTags(c.Tags)
		if err != nil {
			return err
		}
		bind.Append("patch", `"tags" = `+bind.Set("tags", tags))
	}

	if patch := bind.Join("patch", ", "); patch == "" {
		return httpresponse.ErrBadRequest.With("nothing to update")
	} else {
		bind.Set("patch", patch)
	}

	return nil
}
