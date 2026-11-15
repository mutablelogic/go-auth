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
	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// SubjectID selects a subject by its row identifier
type SubjectID uint64

// SubjectMeta inserts and updates a subject
type SubjectMeta cert.SubjectMeta

// SubjectListRequest lists subjects
type SubjectListRequest cert.SubjectListRequest

// Subject reads a subject
type Subject cert.Subject

// SubjectList reads a list of subjects
type SubjectList cert.SubjectList

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
	offsetlimit := pg.OffsetLimit(n.OffsetLimit)
	offsetlimit.Bind(bind, SubjectListLimit)

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

	if subject := n.SubjectMeta.PKIXName().String(); subject != "" {
		n.Subject = types.Ptr(subject)
	} else {
		n.Subject = nil
	}

	// Return success
	return nil
}

func (n *SubjectList) Scan(row pg.Row) error {
	var subject cert.Subject
	if err := (*Subject)(&subject).Scan(row); err != nil {
		return err
	} else {
		n.Body = append(n.Body, subject)
	}
	return nil
}

func (n *SubjectList) ScanCount(row pg.Row) error {
	return row.Scan(&n.Count)
}
