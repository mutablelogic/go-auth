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
	"math/big"
	"strings"
	"time"

	// Packages
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Certificate Name
type CertName string

// Certificate key
type CertKey struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
}

// Name for retrieving private certificate
type PrivateCertName string

// Key for retrieving private certificate
type PrivateCertKey struct {
	Name   string `json:"name"`
	Serial string `json:"serial"`
}

// Certificate Metadata
type CertMeta struct {
	Enabled *bool    `json:"enabled,omitempty" negatable:""`
	Tags    []string `json:"tags,omitempty"`
}

// Certificate
type Cert struct {
	ID uint64 `json:"-" readonly:""`
	CertKey
	Signer    *CertKey    `json:"signer,omitempty"`
	Subject   *SubjectRef `json:"subject,omitempty" readonly:""`
	SubjectID *uint64     `json:"-"`
	SAN       []string    `json:"san,omitempty" readonly:""`
	NotBefore time.Time   `json:"not_before,omitzero"`
	NotAfter  time.Time   `json:"not_after,omitzero"`
	IsCA      bool        `json:"is_ca,omitempty"`
	CertMeta
	Cert          []byte    `json:"cert,omitempty"`
	EffectiveTags []string  `json:"effective_tags,omitempty" readonly:""`
	Ts            time.Time `json:"timestamp,omitzero"`
}

// Composite of Cert and private key for select
type CertWithPrivateKey struct {
	Cert
	PV  uint64 `json:"pv,omitempty" readonly:""`
	Key []byte `json:"key,omitempty"`
}

type CertBundle struct {
	Cert
	Chain []Cert `json:"chain,omitempty" readonly:""`
	Key   []byte `json:"key,omitempty" readonly:""`
}

type CreateCertRequest struct {
	Name    string        `json:"name,omitempty"`
	Expiry  time.Duration `json:"expiry,omitempty"`
	Subject *SubjectMeta  `json:"subject,omitempty"`
	SAN     []string      `json:"san,omitempty"`
	Tags    []string      `json:"tags,omitempty"`
}

type RenewCertRequest struct {
	Expiry  time.Duration `json:"expiry,omitempty"`
	Subject *SubjectMeta  `json:"subject,omitempty"`
}

type CertListRequest struct {
	pg.OffsetLimit
	IsCA    *bool    `json:"is_ca,omitempty"`
	Enabled *bool    `json:"enabled,omitempty" negatable:""`
	Tags    []string `json:"tags,omitempty"`
	Valid   *bool    `json:"valid,omitempty"`
	Subject *uint64  `json:"subject,omitempty"`
}

type CertList struct {
	CertListRequest
	Count uint64 `json:"count"`
	Body  []Cert `json:"body,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c Cert) String() string {
	return types.Stringify(c)
}

func (c CertKey) String() string {
	return types.Stringify(c)
}

func (c CertWithPrivateKey) String() string {
	return types.Stringify(c)
}

func (c CertBundle) String() string {
	return types.Stringify(c)
}

func (c CertMeta) String() string {
	return types.Stringify(c)
}

func (c CreateCertRequest) String() string {
	return types.Stringify(c)
}

func (c RenewCertRequest) String() string {
	return types.Stringify(c)
}

func (c CertListRequest) String() string {
	return types.Stringify(c)
}

func (c CertList) String() string {
	return types.Stringify(c)
}

////////////////////////////////////////////////////////////////////////////////
// SELECTOR

func (c CertName) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if name, err := validateCertName(string(c)); err != nil {
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
	if name, err := validateCertName(string(c)); err != nil {
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
	key, err := validateCertKey(c)
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
	key, err := validateCertKey(CertKey(c))
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
	bind.Append("where", `cert_row."name" <> `+bind.Set("root_name", RootCertName))

	if c.IsCA != nil {
		bind.Append("where", `cert_row."is_ca" = `+bind.Set("is_ca", *c.IsCA))
	}
	if c.Enabled != nil {
		bind.Append("where", `COALESCE(effective.effective_enabled, cert_row."enabled") = `+bind.Set("enabled", *c.Enabled))
	}
	if tags, err := normalizeTags(c.Tags); err != nil {
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
	c.OffsetLimit.Bind(bind, CertListLimit)

	switch op {
	case pg.List:
		return bind.Query("cert.list"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("CertListRequest: operation %q is not supported", op)
	}
}

////////////////////////////////////////////////////////////////////////////////
// READER

func (c *Cert) Scan(row pg.Row) error {
	return scanCert(row, c, nil, nil)
}

func (c *CertWithPrivateKey) Scan(row pg.Row) error {
	return scanCert(row, &c.Cert, &c.Key, &c.PV)
}

func scanCert(row pg.Row, cert *Cert, key *[]byte, pv *uint64) error {
	var enabled bool
	var signerName, signerSerial *string
	var subjectOrg, subjectUnit, subjectCountry, subjectCity, subjectState, subjectStreetAddress, subjectPostalCode *string
	var subjectTs *time.Time

	if key != nil && pv != nil {
		if err := row.Scan(&cert.ID, &cert.Name, &cert.Serial, &cert.SubjectID, &subjectOrg, &subjectUnit, &subjectCountry, &subjectCity, &subjectState, &subjectStreetAddress, &subjectPostalCode, &subjectTs, &signerName, &signerSerial, &cert.Cert, key, &cert.NotBefore, &cert.NotAfter, &cert.IsCA, &enabled, &cert.Tags, &cert.EffectiveTags, pv, &cert.Ts); err != nil {
			return err
		}
	} else {
		if err := row.Scan(&cert.ID, &cert.Name, &cert.Serial, &cert.SubjectID, &subjectOrg, &subjectUnit, &subjectCountry, &subjectCity, &subjectState, &subjectStreetAddress, &subjectPostalCode, &subjectTs, &signerName, &signerSerial, &cert.Cert, &cert.NotBefore, &cert.NotAfter, &cert.IsCA, &enabled, &cert.Tags, &cert.EffectiveTags, &cert.Ts); err != nil {
			return err
		}
	}
	var parsedCert *x509.Certificate
	if value, err := x509.ParseCertificate(cert.Cert); err == nil {
		parsedCert = value
		san := append([]string(nil), value.DNSNames...)
		for _, ip := range value.IPAddresses {
			san = append(san, ip.String())
		}
		if len(san) > 0 {
			cert.SAN = san
		} else {
			cert.SAN = nil
		}
	} else {
		cert.SAN = nil
	}
	if cert.SubjectID != nil {
		meta := SubjectMeta{
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
		cert.Subject = types.Ptr(SubjectRefFromMeta(types.Value(cert.SubjectID), meta, types.Value(subjectTs), commonName))
	} else {
		cert.Subject = nil
	}
	if signerName != nil || signerSerial != nil {
		cert.Signer = &CertKey{Name: strings.TrimSpace(types.Value(signerName)), Serial: strings.TrimSpace(types.Value(signerSerial))}
	} else {
		cert.Signer = nil
	}
	cert.Enabled = types.Ptr(enabled)
	return nil
}

func (c *CertList) Scan(row pg.Row) error {
	var cert Cert
	if err := cert.Scan(row); err != nil {
		return err
	}
	c.Body = append(c.Body, cert)
	return nil
}

func (c *CertList) ScanCount(row pg.Row) error {
	if err := row.Scan(&c.Count); err != nil {
		return err
	}
	c.Clamp(c.Count)
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// WRITER

func (c CertWithPrivateKey) Insert(bind *pg.Bind) (string, error) {
	key, err := validateCertKey(c.CertKey)
	if err != nil {
		return "", err
	}
	bind.Set("name", key.Name)
	bind.Set("serial", key.Serial)

	// Signer
	if c.Signer != nil {
		signer, err := validateCertKey(*c.Signer)
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
	bind.Set("cert", c.Cert.Cert)
	bind.Set("key", c.Key)

	// IsCA
	bind.Set("is_ca", c.IsCA)
	if c.Enabled == nil {
		bind.Set("enabled", true)
	} else {
		bind.Set("enabled", *c.Enabled)
	}
	if tags, err := normalizeTags(c.Tags); err != nil {
		return "", err
	} else {
		bind.Set("tags", tags)
	}
	bind.Set("pv", c.PV)
	if key.Name == RootCertName {
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
		tags, err := normalizeTags(c.Tags)
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

func (c Cert) IsRoot() bool {
	return c.Name == RootCertName
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func normalizeTags(tags []string) ([]string, error) {
	result := make([]string, 0, len(tags))
	seen := make(map[string]struct{}, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			if !types.IsIdentifier(tag) {
				return nil, httpresponse.ErrBadRequest.Withf("tag %q is invalid", tag)
			}
			if _, exists := seen[tag]; exists {
				continue
			}
			seen[tag] = struct{}{}
			result = append(result, tag)
		}
	}
	if result == nil {
		return []string{}, nil
	}
	return result, nil
}

func validateCertKey(key CertKey) (CertKey, error) {
	name, err := validateCertName(key.Name)
	if err != nil {
		return CertKey{}, err
	}
	serial, err := validateCertSerial(key.Serial)
	if err != nil {
		return CertKey{}, err
	}
	return CertKey{Name: name, Serial: serial}, nil
}

func validateCertName(name string) (string, error) {
	if name = strings.TrimSpace(name); name == "" {
		return "", httpresponse.ErrBadRequest.With("name is missing")
	} else if name != RootCertName && !types.IsIdentifier(name) {
		return "", httpresponse.ErrBadRequest.With("name is invalid")
	} else {
		return name, nil
	}
}

func validateCertSerial(serial string) (string, error) {
	serial = strings.TrimSpace(serial)
	if serial == "" {
		return "", httpresponse.ErrBadRequest.With("serial is missing")
	}
	if value, ok := new(big.Int).SetString(serial, 10); !ok || value.Sign() < 0 {
		return "", httpresponse.ErrBadRequest.With("serial is invalid")
	}
	return serial, nil
}
