package schema

import (
	"encoding/json"
	"strings"
	"time"

	auth "github.com/djthorpe/go-auth"

	// Packages
	pg "github.com/mutablelogic/go-pg"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// IdentityKey contains the key for an identity.
type IdentityKey struct {
	Provider string `db:"provider" json:"provider"`
	Sub      string `db:"sub" json:"sub"`
}

// IdentityMeta contains the mutable fields for an identity.
type IdentityMeta struct {
	Email  string         `db:"email" json:"email"`
	Claims map[string]any `db:"claims" json:"claims"`
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
	User       UserID    `db:"user" json:"user"`
	CreatedAt  time.Time `db:"created_at" json:"created_at"`
	ModifiedAt time.Time `db:"modified_at" json:"modified_at"`
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
		return "", auth.ErrNotImplemented.Withf("unsupported IdentityKeySelector operation %q", op)
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
