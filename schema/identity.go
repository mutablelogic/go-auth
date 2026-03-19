package schema

import (
	"encoding/json"
	"strings"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
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
	User       UserID    `json:"user"`
	CreatedAt  time.Time `json:"created_at"`
	ModifiedAt time.Time `json:"modified_at"`
}

// IdentityListRequest contains the query parameters for listing identities.
type IdentityListRequest struct {
	pg.OffsetLimit
	User *uuid.UUID `json:"user,omitempty"`
}

// IdentityList represents a paginated list of identities.
type IdentityList struct {
	pg.OffsetLimit
	Count uint       `json:"count"`
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
	email, _ := claims["email"].(string)

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

func (i IdentityInsert) Name() string {
	for _, key := range []string{"name", "username", "preferred_username", "given_name"} {
		if name, ok := i.Claims[key].(string); ok {
			if name := strings.TrimSpace(name); name != "" {
				return name
			}
		}
	}
	return strings.TrimSpace(i.Email)
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

	if email := canonicalizeEmail(i.Email); email != "" {
		bind.Set("email", email)
	} else {
		bind.Set("email", "")
	}

	if i.Claims == nil {
		i.Claims = map[string]any{}
	}
	claims, err := json.Marshal(i.Claims)
	if err != nil {
		return "", err
	}
	bind.Set("claims", string(claims))

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
		claims, err := json.Marshal(i.Claims)
		if err != nil {
			return err
		}
		bind.Append("patch", "claims = "+bind.Set("claims", string(claims)))
	}

	if patch := bind.Join("patch", ", "); patch == "" {
		return auth.ErrBadParameter.With("no fields to update")
	} else {
		bind.Set("patch", patch)
	}

	return nil
}
