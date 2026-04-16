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
	auth "github.com/mutablelogic/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// IdentityKey contains the key for an identity.
type IdentityKey struct {
	Provider string `json:"provider"`
	Sub      string `json:"sub"`
}

// IdentityMeta contains the mutable fields for an identity.
type IdentityMeta struct {
	Email  string         `json:"email"`
	Claims map[string]any `json:"claims"`
}

// IdentityInsert contains the fields required to create a new identity.
type IdentityInsert struct {
	IdentityKey
	IdentityMeta
}

// Identity represents a stored identity row.
type Identity struct {
	IdentityKey
	IdentityMeta
	User       UserID    `json:"user" format:"uuid" readonly:""`
	CreatedAt  time.Time `json:"created_at" format:"date-time" readonly:""`
	ModifiedAt time.Time `json:"modified_at" format:"date-time" readonly:""`
}

// IdentityListRequest contains the query parameters for listing identities.
type IdentityListRequest struct {
	pg.OffsetLimit
	User *uuid.UUID `json:"user,omitempty" format:"uuid"`
}

// IdentityList represents a paginated list of identities.
type IdentityList struct {
	pg.OffsetLimit
	Count uint       `json:"count" readonly:""`
	Body  []Identity `json:"body,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewIdentityFromClaims(claims map[string]any) (IdentityInsert, error) {
	issuer, ok := claims["iss"].(string)
	if !ok || strings.TrimSpace(issuer) == "" {
		return IdentityInsert{}, auth.ErrBadParameter.With("claims missing iss")
	}
	subject, ok := claims["sub"].(string)
	if !ok || strings.TrimSpace(subject) == "" {
		return IdentityInsert{}, auth.ErrBadParameter.With("claims missing sub")
	}
	rawEmail, _ := claims["email"].(string)
	email := canonicalizeEmail(rawEmail)
	if rawEmail = strings.TrimSpace(rawEmail); rawEmail != "" {
		var normalized string
		if types.IsEmail(rawEmail, nil, &normalized) {
			email = canonicalizeEmail(normalized)
		}
	}

	return IdentityInsert{
		IdentityKey: IdentityKey{
			Provider: issuer,
			Sub:      subject,
		},
		IdentityMeta: IdentityMeta{
			Email:  email,
			Claims: claims,
		},
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (key IdentityKey) String() string {
	return types.Stringify(key)
}

func (key IdentityKey) RedactedString() string {
	r := key
	if r.Sub != "" {
		r.Sub = "[redacted]"
	}
	return types.Stringify(r)
}

func (meta IdentityMeta) String() string {
	return types.Stringify(meta)
}

func (meta IdentityMeta) RedactedString() string {
	r := meta
	if r.Email != "" {
		r.Email = "[redacted]"
	}
	r.Claims = nil
	return types.Stringify(r)
}

func (i IdentityInsert) String() string {
	return types.Stringify(i)
}

func (i IdentityInsert) RedactedString() string {
	r := i
	if r.Email != "" {
		r.Email = "[redacted]"
	}
	return types.Stringify(r)
}

func (i Identity) String() string {
	return types.Stringify(i)
}

func (i Identity) RedactedString() string {
	r := i
	if r.Sub != "" {
		r.Sub = "[redacted]"
	}
	if r.Email != "" {
		r.Email = "[redacted]"
	}
	r.Claims = nil
	return types.Stringify(r)
}

func (req IdentityListRequest) String() string {
	return types.Stringify(req)
}

func (list IdentityList) String() string {
	return types.Stringify(list)
}

func (i IdentityInsert) Name() string {
	for _, key := range []string{"name", "username", "preferred_username", "given_name"} {
		if name, ok := i.Claims[key].(string); ok {
			if name := strings.TrimSpace(name); name != "" {
				return name
			}
		}
	}
	var name, email string
	if types.IsEmail(strings.TrimSpace(i.Email), &name, &email) && strings.TrimSpace(name) != "" {
		return name
	}
	return strings.TrimSpace(email)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

// Select binds the identity key and returns the appropriate named query for
// the given operation (Get, Update or Delete).
func (key IdentityKey) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if provider := strings.TrimSpace(key.Provider); provider == "" {
		return "", auth.ErrBadParameter.With("provider is required")
	} else {
		bind.Set("provider", provider)
	}

	if sub := strings.TrimSpace(key.Sub); sub == "" {
		return "", auth.ErrBadParameter.With("sub is required")
	} else {
		bind.Set("sub", sub)
	}

	switch op {
	case pg.Get:
		return bind.Query("identity.select"), nil
	case pg.Update:
		return bind.Query("identity.update"), nil
	case pg.Delete:
		return bind.Query("identity.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported IdentityKey operation %q", op)
	}
}

func (req IdentityListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Del("where")
	if req.User != nil {
		bind.Append("where", `identity."user" = `+bind.Set("user", *req.User))
	}
	if where := bind.Join("where", " AND "); where == "" {
		bind.Set("where", "")
	} else {
		bind.Set("where", "WHERE "+where)
	}
	bind.Set("orderby", `ORDER BY identity.provider ASC, identity.sub ASC`)

	// Offset and Limit
	req.OffsetLimit.Bind(bind, IdentityListMax)

	switch op {
	case pg.List:
		return bind.Query("identity.list"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported IdentityListRequest operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

// Scan reads a full identity row into the receiver.
// Expected column order: user, provider, sub, email, claims, created_at,
// modified_at.
func (i *Identity) Scan(row pg.Row) error {
	return row.Scan(
		&i.User,
		&i.Provider,
		&i.Sub,
		&i.Email,
		&i.Claims,
		&i.CreatedAt,
		&i.ModifiedAt,
	)
}

func (list *IdentityList) Scan(row pg.Row) error {
	var identity Identity
	if err := identity.Scan(row); err != nil {
		return err
	}
	list.Body = append(list.Body, identity)
	return nil
}

func (list *IdentityList) ScanCount(row pg.Row) error {
	if err := row.Scan(&list.Count); err != nil {
		return err
	}
	list.Clamp(uint64(list.Count))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

// Insert binds all mutable identity fields for an INSERT and returns the named
// query. Immutable fields must already be present in the bind.
func (i IdentityMeta) Insert(bind *pg.Bind) (string, error) {
	if !bind.Has("user") {
		return "", auth.ErrBadParameter.With("user is required")
	}
	if provider, ok := bind.Get("provider").(string); !ok || strings.TrimSpace(provider) == "" {
		return "", auth.ErrBadParameter.With("provider is required")
	}
	if sub, ok := bind.Get("sub").(string); !ok || strings.TrimSpace(sub) == "" {
		return "", auth.ErrBadParameter.With("sub is required")
	}

	// Email
	if email := canonicalizeEmail(i.Email); email != "" {
		bind.Set("email", email)
	} else {
		bind.Set("email", "")
	}

	// Claims
	claims, err := metaInsertExpr(i.Claims)
	if err != nil {
		return "", err
	}
	bind.Set("claims", claims)

	return bind.Query("identity.insert"), nil
}

// Insert binds the identity key and delegates the mutable fields to
// IdentityMeta.Insert. The owning user must already be present in the bind.
func (i IdentityInsert) Insert(bind *pg.Bind) (string, error) {
	if provider := strings.TrimSpace(i.Provider); provider == "" {
		return "", auth.ErrBadParameter.With("provider is required")
	} else {
		bind.Set("provider", provider)
	}
	if sub := strings.TrimSpace(i.Sub); sub == "" {
		return "", auth.ErrBadParameter.With("sub is required")
	} else {
		bind.Set("sub", sub)
	}
	return i.IdentityMeta.Insert(bind)
}

// Update builds a PATCH-style SET clause from whichever fields are non-zero.
func (i IdentityMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")

	if email := canonicalizeEmail(i.Email); email != "" {
		bind.Append("patch", "email = "+bind.Set("email", email))
	}

	if i.Claims != nil {
		expr, err := metaPatchExpr(bind, "claims", "claims", i.Claims)
		if err != nil {
			return err
		}
		bind.Append("patch", "claims = "+expr)
	}

	if patch := bind.Join("patch", ", "); patch == "" {
		return auth.ErrBadParameter.With("no fields to update")
	} else {
		bind.Set("patch", patch)
	}

	return nil
}
