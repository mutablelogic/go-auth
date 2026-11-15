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
	"net/url"
	"strings"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type CredentialKey struct {
	Key string `json:"key" help:"Credential key"`
}

// Credential is the public credential row returned from the database.
// Secret material and passphrase version are intentionally excluded.
type Credential struct {
	CredentialKey
	UpdatedAt time.Time `json:"updated_at" help:"Update timestamp" readonly:""`
}

// CredentialCreate contains the values required to create a credential row.
// The returned Credential omits PV and Credentials.
type CredentialCreate struct {
	CredentialKey
	Credentials any `json:"credentials" help:"Credential value"`
}

// CredentialGet contains the values required to retrieve a credential row.
// The returned Credential includes PV and Credentials.
type CredentialGet struct {
	CredentialKey
	PV          uint64 `json:"pv" help:"Passphrase version"`
	Credentials any    `json:"credentials" help:"Credential value"`
}

// CredentialRotate replaces the encrypted credentials for a key, but only if
// they are still the old encrypted credentials, so that credentials changed
// or deleted in the meantime are not overwritten.
type CredentialRotate struct {
	CredentialKey
	PV             uint64
	Credentials    []byte
	OldPV          uint64
	OldCredentials []byte
}

type CredentialListRequest struct {
	pg.OffsetLimit
	Rotate *bool `json:"rotate,omitempty" help:"Filter credentials by whether they need rotating to the latest passphrase version. All credentials are listed when not set." negatable:""`
}

type CredentialList struct {
	CredentialListRequest
	Count uint64        `json:"count,omitempty"`
	Body  []*Credential `json:"body,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (c Credential) String() string {
	return types.Stringify(c)
}

func (c CredentialCreate) String() string {
	return types.Stringify(c)
}

func (c CredentialCreate) RedactedString() string {
	r := c
	r.Credentials = nil
	return types.Stringify(r)
}

func (c CredentialListRequest) String() string {
	return types.Stringify(c)
}

func (c CredentialList) String() string {
	return types.Stringify(c)
}

////////////////////////////////////////////////////////////////////////////////
// QUERY

func (r CredentialListRequest) Query() url.Values {
	query := url.Values{}
	if r.Rotate != nil {
		query.Set("rotate", types.Stringify(types.Value(r.Rotate)))
	}
	if r.Offset > 0 {
		query.Set("offset", types.Stringify(r.Offset))
	}
	if r.Limit != nil {
		query.Set("limit", types.Stringify(types.Value(r.Limit)))
	}
	return query
}

////////////////////////////////////////////////////////////////////////////////
// TABLE OUTPUT

func (r Credential) Header() []string {
	return []string{"Key", "Updated At"}
}

func (r Credential) Width(col int) int {
	return 0
}

func (r Credential) Cell(col int) string {
	switch col {
	case 0:
		return r.Key
	case 1:
		return r.UpdatedAt.Format(time.RFC3339)
	default:
		return ""
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - VALIDATE

// Validate returns an error if the key, with surrounding spaces removed, is
// not an identifier
func (c CredentialKey) Validate() error {
	_, err := c.key()
	return err
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

func (c CredentialKey) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if key, err := c.key(); err != nil {
		return "", err
	} else {
		bind.Set("key", key)
	}

	switch op {
	case pg.Get:
		if bind.Has("meta") {
			return bind.Query("credential.get_meta"), nil
		} else if bind.Has("pv") {
			return bind.Query("credential.get_pv"), nil
		} else {
			return bind.Query("credential.get"), nil
		}
	case pg.Delete:
		return bind.Query("credential.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported CredentialKey operation %q", op)
	}
}

func (c *CredentialListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	c.OffsetLimit.Bind(bind, CredentialListLimit)

	switch op {
	case pg.List:
		if c.Rotate != nil && bind.Has("latestpv") {
			if *c.Rotate {
				bind.Set("where", `WHERE "pv" != CAST(@latestpv AS INT)`)
			} else {
				bind.Set("where", `WHERE "pv" = CAST(@latestpv AS INT)`)
			}
		} else {
			bind.Set("where", "")
		}
		return bind.Query("credential.list"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported CredentialListRequest operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

// Expected column order: key, updated_at.
func (c *Credential) Scan(row pg.Row) error {
	if err := row.Scan(&c.Key, &c.UpdatedAt); err != nil {
		return err
	}
	return nil
}

// Expected column order: key, credential.
func (c *CredentialCreate) Scan(row pg.Row) error {
	if err := row.Scan(&c.Key, &c.Credentials); err != nil {
		return err
	}
	return nil
}

// Expected column order: key, pv, credential.
func (c *CredentialGet) Scan(row pg.Row) error {
	if err := row.Scan(&c.Key, &c.PV, &c.Credentials); err != nil {
		return err
	}
	return nil
}

func (c *CredentialList) Scan(rows pg.Row) error {
	var credential Credential
	if err := credential.Scan(rows); err != nil {
		return err
	}
	c.Body = append(c.Body, &credential)
	return nil
}

func (c *CredentialList) ScanCount(row pg.Row) error {
	return row.Scan(&c.Count)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

func (c CredentialCreate) Insert(bind *pg.Bind) (string, error) {
	if key, err := c.key(); err != nil {
		return "", err
	} else {
		bind.Set("key", key)
	}

	if isEmptyCredential(c.Credentials) {
		return "", auth.ErrBadParameter.With("credentials are required")
	} else if !bind.Has("pv") {
		return "", auth.ErrInternalServerError.With("credential create requires passphrase version binding")
	} else {
		bind.Set("credentials", c.Credentials)
	}
	return bind.Query("credential.upsert"), nil
}

func (c CredentialRotate) Insert(bind *pg.Bind) (string, error) {
	if key, err := c.key(); err != nil {
		return "", err
	} else {
		bind.Set("key", key)
	}
	if c.PV == 0 || len(c.Credentials) == 0 || len(c.OldCredentials) == 0 {
		return "", auth.ErrInternalServerError.With("credential rotate requires the new and old credentials")
	}
	bind.Set("pv", c.PV)
	bind.Set("credentials", c.Credentials)
	bind.Set("oldpv", c.OldPV)
	bind.Set("oldcredentials", c.OldCredentials)
	return bind.Query("credential.rotate"), nil
}

func (c CredentialRotate) Update(_ *pg.Bind) error {
	return auth.ErrNotImplemented.With("CredentialRotate: update: not supported")
}

func (c CredentialCreate) Update(_ *pg.Bind) error {
	return auth.ErrNotImplemented.With("CredentialCreate: update: not supported")
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// key returns the key with surrounding spaces removed, or an error if it is
// not an identifier
func (c CredentialKey) key() (string, error) {
	if key := strings.TrimSpace(c.Key); !types.IsIdentifier(key) {
		return "", auth.ErrBadParameter.With("credential key must be a non-empty identifier")
	} else {
		return key, nil
	}
}

func isEmptyCredential(v any) bool {
	switch value := v.(type) {
	case nil:
		return true
	case []byte:
		return len(value) == 0
	case string:
		return value == ""
	default:
		return false
	}
}
