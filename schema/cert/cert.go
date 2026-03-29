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

// Certificate Metadata
type CertMeta struct {
	Signer    *string   `json:"signer,omitempty"`
	Subject   *uint64   `json:"subject,omitempty"`
	NotBefore time.Time `json:"not_before,omitzero"`
	NotAfter  time.Time `json:"not_after,omitzero"`
	IsCA      bool      `json:"is_ca,omitempty"`
	Enabled   *bool     `json:"enabled,omitempty" negatable:""`
	Tags      []string  `json:"tags,omitempty"`
	PV        uint64    `json:"pv,omitempty"`
	Cert      []byte    `json:"cert,omitempty"`
	Key       []byte    `json:"key,omitempty"`
}

// Certificate Metadata
type Cert struct {
	Name string `json:"name"`
	CertMeta
	EffectiveTags []string  `json:"effective_tags,omitempty" readonly:""`
	Ts            time.Time `json:"timestamp,omitzero"`
}

type CreateCertRequest struct {
	Name    string        `json:"name,omitempty"`
	Expiry  time.Duration `json:"expiry,omitempty"`
	Subject *SubjectMeta  `json:"subject,omitempty"`
	Enabled *bool         `json:"enabled,omitempty" negatable:""`
	Tags    []string      `json:"tags,omitempty"`
}

type CertListRequest struct {
	pg.OffsetLimit
	IsCA    *bool   `json:"is_ca,omitempty"`
	Enabled *bool   `json:"enabled,omitempty" negatable:""`
	Valid   *bool   `json:"valid,omitempty"`
	Subject *uint64 `json:"subject,omitempty"`
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

func (c CertMeta) String() string {
	return types.Stringify(c)
}

func (c CreateCertRequest) String() string {
	return types.Stringify(c)
}

func (c CertListRequest) String() string {
	return types.Stringify(c)
}

func (c CertList) String() string {
	return types.Stringify(c)
}

////////////////////////////////////////////////////////////////////////////////
// DELECTOR

func (c CertName) Select(bind *pg.Bind, op pg.Op) (string, error) {
	// Name
	if name := string(c); name == "" {
		return "", httpresponse.ErrBadRequest.With("name is missing")
	} else if name != RootCertName && !types.IsIdentifier(name) {
		return "", httpresponse.ErrBadRequest.With("name is invalid")
	} else {
		bind.Set("name", name)
	}

	switch op {
	case pg.Get:
		return bind.Query("cert.select"), nil
	case pg.Delete:
		return bind.Query("cert.delete"), nil
	default:
		return "", httpresponse.ErrBadRequest.Withf("CertName: operation %q is not supported", op)
	}
}

func (c CertListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Del("where")

	if c.IsCA != nil {
		bind.Append("where", `cert_row."is_ca" = `+bind.Set("is_ca", *c.IsCA))
	}
	if c.Enabled != nil {
		bind.Append("where", `cert_row."enabled" = `+bind.Set("enabled", *c.Enabled))
	}
	if c.Valid != nil {
		if *c.Valid {
			bind.Append("where", `cert_row."not_before" <= CURRENT_TIMESTAMP AND cert_row."not_after" > CURRENT_TIMESTAMP`)
		} else {
			bind.Append("where", `(cert_row."not_before" > CURRENT_TIMESTAMP OR cert_row."not_after" <= CURRENT_TIMESTAMP)`)
		}
	}
	if c.Subject != nil {
		if *c.Subject == 0 {
			return "", httpresponse.ErrBadRequest.With("subject is invalid")
		}
		bind.Append("where", `cert_row."subject" = `+bind.Set("subject", *c.Subject))
	}

	if where := bind.Join("where", " AND "); where == "" {
		bind.Set("where", "")
	} else {
		bind.Set("where", "WHERE "+where)
	}
	bind.Set("orderby", `ORDER BY cert_row."name" ASC`)
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
	var enabled bool

	// Scan the row
	if err := row.Scan(&c.Name, &c.Subject, &c.Signer, &c.Cert, &c.Key, &c.NotBefore, &c.NotAfter, &c.IsCA, &enabled, &c.Tags, &c.EffectiveTags, &c.PV, &c.Ts); err != nil {
		return err
	}
	c.Enabled = types.Ptr(enabled)
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

func (c CertMeta) Insert(bind *pg.Bind) (string, error) {
	name := ""

	// Name
	if !bind.Has("name") {
		return "", httpresponse.ErrBadRequest.With("name is missing")
	} else if value, ok := bind.Get("name").(string); !ok {
		return "", httpresponse.ErrBadRequest.With("name is invalid")
	} else if value = strings.TrimSpace(value); value == "" {
		return "", httpresponse.ErrBadRequest.With("name is missing")
	} else if value != RootCertName && !types.IsIdentifier(value) {
		return "", httpresponse.ErrBadRequest.With("name is invalid")
	} else {
		name = value
		bind.Set("name", name)
	}

	// Signer
	bind.Set("signer", c.Signer)

	// Subject
	if subject := types.PtrUint64(c.Subject); subject == 0 {
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
	bind.Set("cert", c.Cert)
	bind.Set("key", c.Key)

	// IsCA
	bind.Set("is_ca", c.IsCA)
	if c.Enabled == nil {
		bind.Set("enabled", true)
	} else {
		bind.Set("enabled", *c.Enabled)
	}
	bind.Set("tags", normalizeTags(c.Tags))
	bind.Set("pv", c.PV)
	if name == RootCertName {
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

func (c CertMeta) Update(bind *pg.Bind) error {
	return httpresponse.ErrNotImplemented
}

func (c Cert) IsRoot() bool {
	return c.Name == RootCertName
}

func normalizeTags(tags []string) []string {
	result := make([]string, 0, len(tags))
	for _, tag := range tags {
		if tag = strings.TrimSpace(tag); tag != "" {
			result = append(result, tag)
		}
	}
	if result == nil {
		return []string{}
	}
	return result
}
