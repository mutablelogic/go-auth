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
	"crypto/x509/pkix"
	"time"

	// Packages
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

type SubjectID uint64

type SubjectMeta struct {
	Org           *string `json:"organizationName,omitempty"`
	Unit          *string `json:"organizationalUnit,omitempty"`
	Country       *string `json:"countryName,omitempty"`
	City          *string `json:"localityName,omitempty"`
	State         *string `json:"stateOrProvinceName,omitempty"`
	StreetAddress *string `json:"streetAddress,omitempty"`
	PostalCode    *string `json:"postalCode,omitempty"`
}

type Subject struct {
	ID uint64 `json:"id"`
	SubjectMeta
	Ts      time.Time `json:"timestamp,omitzero"`
	Subject *string   `json:"subject,omitempty"`
}

type SubjectRef struct {
	ID uint64 `json:"id"`
	SubjectMeta
	Ts   time.Time `json:"timestamp,omitzero"`
	Name *string   `json:"name,omitempty"`
}

type SubjectListRequest struct {
	pg.OffsetLimit
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
		return types.Ptr(values[0])
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

func pkixNameFromSubjectMeta(subject SubjectMeta) pkix.Name {
	fieldValues := func(value *string) []string {
		if value == nil {
			return nil
		}
		return []string{types.Value(value)}
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

////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

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

////////////////////////////////////////////////////////////////////////////////
// SELECT

func (n SubjectID) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if n == 0 {
		return "", httpresponse.ErrBadRequest.With("id is missing")
	} else {
		bind.Set("id", n)
	}

	// Return query
	switch op {
	case pg.Get:
		return bind.Query("subject.select"), nil
	case pg.Update:
		return bind.Query("subject.update"), nil
	case pg.Delete:
		return bind.Query("subject.delete"), nil
	default:
		return "", httpresponse.ErrInternalError.Withf("unsupported SubjectID operation %q", op)
	}
}

func (n SubjectListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	// Set empty where
	bind.Set("where", "")

	// Bind offset and limit
	n.OffsetLimit.Bind(bind, SubjectListLimit)

	// Return query
	switch op {
	case pg.List:
		return bind.Query("subject.list"), nil
	default:
		return "", httpresponse.ErrInternalError.Withf("unsupported SubjectListRequest operation %q", op)
	}
}

////////////////////////////////////////////////////////////////////////////////
// WRITER

func (n SubjectMeta) Insert(bind *pg.Bind) (string, error) {
	bind.Set("organizationName", types.TrimStringPtr(n.Org))
	bind.Set("organizationalUnit", types.TrimStringPtr(n.Unit))
	bind.Set("countryName", types.TrimStringPtr(n.Country))
	bind.Set("localityName", types.TrimStringPtr(n.City))
	bind.Set("stateOrProvinceName", types.TrimStringPtr(n.State))
	bind.Set("streetAddress", types.TrimStringPtr(n.StreetAddress))
	bind.Set("postalCode", types.TrimStringPtr(n.PostalCode))

	// Return insert or replace
	return bind.Query("subject.insert"), nil
}

func (n SubjectMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")
	if n.Org != nil {
		bind.Append("patch", `"organizationName" = `+bind.Set("organizationName", types.TrimStringPtr(n.Org)))
	}
	if n.Unit != nil {
		bind.Append("patch", `"organizationalUnit" = `+bind.Set("organizationalUnit", types.TrimStringPtr(n.Unit)))
	}
	if n.Country != nil {
		bind.Append("patch", `"countryName" = `+bind.Set("countryName", types.TrimStringPtr(n.Country)))
	}
	if n.City != nil {
		bind.Append("patch", `"localityName" = `+bind.Set("localityName", types.TrimStringPtr(n.City)))
	}
	if n.State != nil {
		bind.Append("patch", `"stateOrProvinceName" = `+bind.Set("stateOrProvinceName", types.TrimStringPtr(n.State)))
	}
	if n.StreetAddress != nil {
		bind.Append("patch", `"streetAddress" = `+bind.Set("streetAddress", types.TrimStringPtr(n.StreetAddress)))
	}
	if n.PostalCode != nil {
		bind.Append("patch", `"postalCode" = `+bind.Set("postalCode", types.TrimStringPtr(n.PostalCode)))
	}

	// Join the patch fields
	if patch := bind.Join("patch", ", "); patch == "" {
		return httpresponse.ErrBadRequest.With("nothing to update")
	} else {
		bind.Set("patch", patch)
	}

	// Return success
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// READER

func (n *Subject) Scan(row pg.Row) error {
	// Scan from row
	if err := row.Scan(&n.ID, &n.Org, &n.Unit, &n.Country, &n.City, &n.State, &n.StreetAddress, &n.PostalCode, &n.Ts); err != nil {
		return err
	}

	if subject := pkixNameFromSubjectMeta(n.SubjectMeta).String(); subject != "" {
		n.Subject = types.Ptr(subject)
	} else {
		n.Subject = nil
	}

	// Return success
	return nil
}

func (n *SubjectList) Scan(row pg.Row) error {
	var subject Subject
	if err := subject.Scan(row); err != nil {
		return err
	} else {
		n.Body = append(n.Body, subject)
	}
	return nil
}

func (n *SubjectList) ScanCount(row pg.Row) error {
	return row.Scan(&n.Count)
}

func SubjectRefFromMeta(id uint64, meta SubjectMeta, ts time.Time) SubjectRef {
	ref := SubjectRef{
		ID:          id,
		SubjectMeta: meta,
		Ts:          ts,
	}
	if name := pkixNameFromSubjectMeta(meta).String(); name != "" {
		ref.Name = types.Ptr(name)
	}
	return ref
}
