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

package cert

import (
	"crypto/x509/pkix"
	"math/big"
	"net/url"
	"strconv"
	"strings"
	"time"

	// Packages
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

// The certificate API's types, which don't depend on how they're stored.
// The PostgreSQL store's queries, and the bindings of these types to them,
// are in cert/schema.

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// RootCertName is the name of the root certificate, which signs the
	// certificate authorities
	RootCertName = "$root$"
)

const (
	// ScopeCertRead grants permission to list certificates, and get them and
	// their chains, without their private keys
	ScopeCertRead = "cert:read"

	// ScopeCertWrite grants permission to create, renew and update
	// certificate authorities and certificates
	ScopeCertWrite = "cert:write"

	// ScopeCertKey grants permission to get a leaf certificate's private key
	ScopeCertKey = "cert:key"
)

const (
	// DefaultCACertExpiry is the default validity period for intermediate
	// certificate authorities.
	DefaultCACertExpiry = 5 * 365 * 24 * time.Hour

	// DefaultRootExpiry is the validity period of a generated root
	// certificate.
	DefaultRootExpiry = 10 * 365 * 24 * time.Hour

	// DefaultCertExpiry is the default validity period for leaf certificates.
	DefaultCertExpiry = 90 * 24 * time.Hour
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// OffsetLimit pages a list
type OffsetLimit struct {
	Offset uint64  `json:"offset,omitempty" help:"Offset within the result set" jsonschema:"Offset for pagination" example:"0"`
	Limit  *uint64 `json:"limit,omitempty" help:"Number of items to return" jsonschema:"Limit for pagination" example:"100"`
}

// Certificate key
type CertKey struct {
	Name   string `json:"name" example:"my_cert"`
	Serial string `json:"serial" example:"123456789"`
}

// Certificate Metadata
type CertMeta struct {
	Enabled *bool    `json:"enabled,omitempty" negatable:""`
	Tags    []string `json:"tags,omitempty"`
}

// Certificate is a stored certificate, without its private key
type Certificate struct {
	ID uint64 `json:"-" readonly:""`
	CertKey
	Signer    *CertKey    `json:"signer,omitempty" jsonschema:"certificate authority that signed this certificate"`
	Subject   *SubjectRef `json:"subject,omitempty" readonly:"" jsonschema:"certificate subject details"`
	SubjectID *uint64     `json:"-"`
	SAN       []string    `json:"san,omitempty" readonly:"" jsonschema:"subject alternative names: DNS names, wildcards and IP addresses" example:"[\"*.example.com\",\"192.168.1.1\"]"`
	NotBefore time.Time   `json:"not_before,omitzero" jsonschema:"start of certificate validity period" example:"2026-01-01T00:00:00Z"`
	NotAfter  time.Time   `json:"not_after,omitzero" jsonschema:"end of certificate validity period" example:"2027-01-01T00:00:00Z"`
	IsCA      bool        `json:"is_ca,omitempty" jsonschema:"whether this is a certificate authority" example:"false"`
	CertMeta
	Cert          []byte    `json:"cert,omitempty" jsonschema:"DER-encoded certificate data"`
	EffectiveTags []string  `json:"effective_tags,omitempty" readonly:"" jsonschema:"tags inherited from the signing chain" example:"[\"production\",\"web\"]"`
	Ts            time.Time `json:"timestamp,omitzero" jsonschema:"last modification timestamp"`
}

// Composite of Cert and private key for select
type CertWithPrivateKey struct {
	Certificate
	PV  uint64 `json:"pv,omitempty" readonly:"" jsonschema:"private key version"`
	Key []byte `json:"key,omitempty" jsonschema:"DER-encoded private key data"`
}

type CertBundle struct {
	Certificate
	Chain []Certificate `json:"chain,omitempty" readonly:""`
	Key   []byte        `json:"key,omitempty" readonly:""`
}

type CreateCertRequest struct {
	Name    string        `json:"name,omitempty" jsonschema:"unique certificate name" example:"my_cert"`
	Expiry  time.Duration `json:"expiry,omitempty" jsonschema:"certificate validity duration" example:"8760h"`
	Subject *SubjectMeta  `json:"subject,omitempty" optional:"" jsonschema:"certificate subject details"`
	SAN     []string      `json:"san,omitempty" optional:"" jsonschema:"subject alternative names: DNS names, wildcards and IP addresses" example:"[\"*.example.com\",\"192.168.1.1\"]"`
	Tags    []string      `json:"tags,omitempty" jsonschema:"labels for grouping and filtering certificates" example:"[\"tag1\",\"tag2\"]"`
}

type RenewCertRequest struct {
	Expiry  time.Duration `json:"expiry,omitempty" jsonschema:"new certificate validity duration" example:"8760h"`
	Subject *SubjectMeta  `json:"subject,omitempty" jsonschema:"updated certificate subject details"`
}

// Features is what the server's certificate manager can do, which its web UI
// reads from the configuration's cert section: Root is true when a root is
// stored, without which certificate authorities can't be created
type Features struct {
	Root bool `json:"root"`
}

// GetCertRequest is what's returned with a certificate
type GetCertRequest struct {
	Chain bool `json:"chain,omitempty" help:"Include the issuer chain, up to the root"`
}

type CertListRequest struct {
	OffsetLimit
	IsCA    *bool    `json:"is_ca,omitempty" jsonschema:"filter by certificate authority status" example:"true"`
	Enabled *bool    `json:"enabled,omitempty" negatable:"" jsonschema:"filter by effective enabled state" example:"true"`
	Tags    []string `json:"tags,omitempty" jsonschema:"require all specified effective tags" example:"[\"production\"]"`
	Valid   *bool    `json:"valid,omitempty" jsonschema:"filter by current validity window" example:"true"`
	Subject *uint64  `json:"subject,omitempty" jsonschema:"filter by subject row identifier" example:"1"`
	Latest  *bool    `json:"latest,omitempty" negatable:"" jsonschema:"only each certificate's latest version, which can be renewed and sign certificates, or with false, only their older versions" example:"true"`
	Name    string   `json:"name,omitempty" jsonschema:"only the versions of the certificate with the name, the latest first" example:"web"`
}

type CertList struct {
	CertListRequest
	Count uint64        `json:"count"`
	Body  []Certificate `json:"body,omitempty"`
}

type SubjectMeta struct {
	Org           *string `json:"organizationName,omitempty" example:"Example Corp"`
	Unit          *string `json:"organizationalUnit,omitempty" example:"IT Department"`
	Country       *string `json:"countryName,omitempty" example:"US"`
	City          *string `json:"localityName,omitempty" example:"San Francisco"`
	State         *string `json:"stateOrProvinceName,omitempty" example:"California"`
	StreetAddress *string `json:"streetAddress,omitempty" example:"123 Main St"`
	PostalCode    *string `json:"postalCode,omitempty" example:"94105"`
}

// Subject is a stored subject, which certificates share, with the number of
// certificates which use it: one which none uses can be changed or deleted
type Subject struct {
	ID uint64 `json:"id" readonly:""`
	SubjectMeta
	Ts      time.Time `json:"timestamp,omitzero" readonly:""`
	Subject *string   `json:"subject,omitempty" readonly:""`
	Certs   uint64    `json:"certs" readonly:"" help:"Number of certificates which use the subject"`
}

type SubjectRef struct {
	ID uint64 `json:"id" help:"The subject's identifier"`
	SubjectMeta
	Ts         time.Time `json:"timestamp,omitzero"`
	CommonName *string   `json:"commonName,omitempty"`
	Name       *string   `json:"name,omitempty"`
}

type SubjectListRequest struct {
	OffsetLimit
}

type SubjectList struct {
	SubjectListRequest
	Count uint64    `json:"count"`
	Body  []Subject `json:"body,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func SubjectMetaFromPKIXName(subject pkix.Name) SubjectMeta {
	fieldPtr := func(values []string) *string {
		if len(values) == 0 {
			return nil
		}
		if value := strings.TrimSpace(values[0]); value != "" {
			return types.Ptr(value)
		}
		return nil
	}
	return SubjectMeta{
		Org:           fieldPtr(subject.Organization),
		Unit:          fieldPtr(subject.OrganizationalUnit),
		Country:       fieldPtr(subject.Country),
		City:          fieldPtr(subject.Locality),
		State:         fieldPtr(subject.Province),
		StreetAddress: fieldPtr(subject.StreetAddress),
		PostalCode:    fieldPtr(subject.PostalCode),
	}
}

func MergeSubjectMeta(base SubjectMeta, patch *SubjectMeta) SubjectMeta {
	if patch == nil {
		return normalizeSubjectMeta(base)
	}

	merged := normalizeSubjectMeta(base)
	merged.Org = mergeSubjectValue(merged.Org, patch.Org)
	merged.Unit = mergeSubjectValue(merged.Unit, patch.Unit)
	merged.Country = mergeSubjectValue(merged.Country, patch.Country)
	merged.City = mergeSubjectValue(merged.City, patch.City)
	merged.State = mergeSubjectValue(merged.State, patch.State)
	merged.StreetAddress = mergeSubjectValue(merged.StreetAddress, patch.StreetAddress)
	merged.PostalCode = mergeSubjectValue(merged.PostalCode, patch.PostalCode)

	return merged
}

// PKIXName is the subject as an X.509 name, without its common name
func (subject SubjectMeta) PKIXName() pkix.Name {
	fieldValues := func(value *string) []string {
		if value == nil {
			return nil
		}
		if value := strings.TrimSpace(types.Value(value)); value != "" {
			return []string{value}
		}
		return nil
	}

	return pkix.Name{
		Organization:       fieldValues(subject.Org),
		OrganizationalUnit: fieldValues(subject.Unit),
		Country:            fieldValues(subject.Country),
		Locality:           fieldValues(subject.City),
		Province:           fieldValues(subject.State),
		StreetAddress:      fieldValues(subject.StreetAddress),
		PostalCode:         fieldValues(subject.PostalCode),
	}
}

func normalizeSubjectMeta(subject SubjectMeta) SubjectMeta {
	subject.Org = normalizeSubjectValue(subject.Org)
	subject.Unit = normalizeSubjectValue(subject.Unit)
	subject.Country = normalizeSubjectValue(subject.Country)
	subject.City = normalizeSubjectValue(subject.City)
	subject.State = normalizeSubjectValue(subject.State)
	subject.StreetAddress = normalizeSubjectValue(subject.StreetAddress)
	subject.PostalCode = normalizeSubjectValue(subject.PostalCode)
	return subject
}

func mergeSubjectValue(base, patch *string) *string {
	if patch == nil {
		return normalizeSubjectValue(base)
	}
	return normalizeSubjectValue(patch)
}

func normalizeSubjectValue(value *string) *string {
	if value == nil {
		return nil
	}
	if trimmed := strings.TrimSpace(*value); trimmed != "" {
		return types.Ptr(trimmed)
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c Certificate) String() string {
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

func (n SubjectMeta) String() string {
	return types.Stringify(n)
}

func (n Subject) String() string {
	return types.Stringify(n)
}

func (n SubjectRef) String() string {
	return types.Stringify(n)
}

func (n SubjectList) String() string {
	return types.Stringify(n)
}

func (n SubjectListRequest) String() string {
	return types.Stringify(n)
}

func SubjectRefFromMeta(id uint64, meta SubjectMeta, ts time.Time, commonName *string) SubjectRef {
	ref := SubjectRef{
		ID:          id,
		SubjectMeta: meta,
		Ts:          ts,
		CommonName:  commonName,
	}
	pkixName := meta.PKIXName()
	if commonName != nil {
		pkixName.CommonName = types.Value(commonName)
	}
	if name := pkixName.String(); name != "" {
		ref.Name = types.Ptr(name)
	}
	return ref
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Query is the request as URL query parameters
func (r GetCertRequest) Query() url.Values {
	query := url.Values{}
	if r.Chain {
		query.Set("chain", "true")
	}
	return query
}

// Query is the request as URL query parameters
func (r SubjectListRequest) Query() url.Values {
	query := url.Values{}
	if r.Offset > 0 {
		query.Set("offset", strconv.FormatUint(r.Offset, 10))
	}
	if r.Limit != nil {
		query.Set("limit", strconv.FormatUint(*r.Limit, 10))
	}
	return query
}

// Query is the request as URL query parameters
func (r CertListRequest) Query() url.Values {
	query := url.Values{}
	if r.Offset > 0 {
		query.Set("offset", strconv.FormatUint(r.Offset, 10))
	}
	if r.Limit != nil {
		query.Set("limit", strconv.FormatUint(*r.Limit, 10))
	}
	if r.IsCA != nil {
		query.Set("is_ca", strconv.FormatBool(*r.IsCA))
	}
	if r.Enabled != nil {
		query.Set("enabled", strconv.FormatBool(*r.Enabled))
	}
	for _, tag := range r.Tags {
		query.Add("tags", tag)
	}
	if r.Valid != nil {
		query.Set("valid", strconv.FormatBool(*r.Valid))
	}
	if r.Subject != nil {
		query.Set("subject", strconv.FormatUint(*r.Subject, 10))
	}
	if r.Latest != nil {
		query.Set("latest", strconv.FormatBool(*r.Latest))
	}
	if r.Name != "" {
		query.Set("name", r.Name)
	}
	return query
}

// IsRoot is true for the root certificate
func (c Certificate) IsRoot() bool {
	return c.Name == RootCertName
}

////////////////////////////////////////////////////////////////////////////////
// VALIDATION

// NormalizeTags trims tags, drops empty and repeated ones, and fails when
// one isn't an identifier
func NormalizeTags(tags []string) ([]string, error) {
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

// Validate is the key, trimmed, or an error when its name or serial is
// invalid
func (key CertKey) Validate() (CertKey, error) {
	name, err := ValidateCertName(key.Name)
	if err != nil {
		return CertKey{}, err
	}
	serial, err := validateCertSerial(key.Serial)
	if err != nil {
		return CertKey{}, err
	}
	return CertKey{Name: name, Serial: serial}, nil
}

// ValidateCertName is the name, trimmed, or an error when it isn't an
// identifier, or the root certificate's name
func ValidateCertName(name string) (string, error) {
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
