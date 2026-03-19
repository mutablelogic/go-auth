package schema

import (
	"encoding/json"
	"slices"
	"strings"
	"time"

	auth "github.com/djthorpe/go-auth"

	// Packages
	"github.com/google/uuid"
	"github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// UserStatus represents the lifecycle state of a user account.
type UserStatus string

// UserID is a unique identifier for a user account. It is generated as a UUID.
type UserID uuid.UUID

// UserMeta contains the mutable profile fields of a user.
// Email is the canonical address used to merge logins across providers.
type UserMeta struct {
	Name      string         `db:"name" json:"name"`
	Email     string         `db:"email" json:"email"`
	Status    *UserStatus    `db:"status" json:"status,omitempty"`
	Meta      map[string]any `db:"meta" json:"meta,omitempty"`
	ExpiresAt *time.Time     `db:"expires_at" json:"expires_at,omitzero"`
}

// User represents a user account in the system. It contains both
// immutable and mutable fields.
type User struct {
	ID         UserID         `db:"id" json:"id"`
	CreatedAt  time.Time      `db:"created_at" json:"created_at"`
	ModifiedAt *time.Time     `db:"modified_at" json:"modified_at,omitempty"`
	Claims     map[string]any `db:"claims" json:"claims,omitempty"`
	Groups     []string       `db:"groups" json:"groups,omitempty"`
	Scopes     []string       `db:"scopes" json:"scopes,omitempty"`
	UserMeta
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	UserStatusNew       UserStatus = "new"
	UserStatusActive    UserStatus = "active"
	UserStatusInactive  UserStatus = "inactive"
	UserStatusSuspended UserStatus = "suspended"
	UserStatusDeleted   UserStatus = "deleted"
)

var (
	allUserStatus = []UserStatus{
		UserStatusNew,
		UserStatusActive,
		UserStatusInactive,
		UserStatusSuspended,
		UserStatusDeleted,
	}
)

// IsValidUserStatus returns true when status is one of the supported values.
func IsValidUserStatus(status UserStatus) bool {
	return slices.Contains(allUserStatus, status)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - UUID

func (id UserID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *UserID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	} else if uid, err := uuid.Parse(strings.Trim(s, `"`)); err != nil {
		return err
	} else if uid == uuid.Nil {
		return auth.ErrBadParameter.With("id cannot be nil")
	} else {
		*id = UserID(uid)
	}

	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

// Select binds the user ID and returns the appropriate named query for the
// given operation (Get, Update or Delete).
func (user UserID) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(user))
	switch op {
	case pg.Get:
		return bind.Query("user.select"), nil
	case pg.Update:
		return bind.Query("user.update"), nil
	case pg.Delete:
		return bind.Query("user.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported UserIDSelector operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

// Scan reads a full user row into the receiver.
// Expected column order: id, name, email, meta, status, created_at,
// expires_at, modified_at, claims, groups, scopes.
func (u *User) Scan(row pg.Row) error {
	return row.Scan(
		&u.ID,
		&u.Name,
		&u.Email,
		&u.Meta,
		&u.Status,
		&u.CreatedAt,
		&u.ExpiresAt,
		&u.ModifiedAt,
		&u.Claims,
		&u.Groups,
		&u.Scopes,
	)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

// Insert binds all UserMeta fields for an INSERT and returns the named query.
func (u UserMeta) Insert(bind *pg.Bind) (string, error) {
	// Fix meta
	if u.Meta == nil {
		u.Meta = map[string]any{}
	}

	// Validate email and name, which are required for user creation.
	var name, email string
	if email_ := strings.TrimSpace(u.Email); email_ != "" {
		if !types.IsEmail(email_, &name, &email) {
			return "", auth.ErrBadParameter.Withf("invalid email address %q", u.Email)
		} else {
			bind.Set("email", canonicalizeEmail(email))
		}
	} else {
		return "", auth.ErrBadParameter.With("email is required")
	}
	if name_ := strings.TrimSpace(u.Name); name_ != "" {
		name = name_
	}
	if name == "" {
		return "", auth.ErrBadParameter.With("name is required")
	} else {
		bind.Set("name", name)
	}

	// Convert meta to JSON string
	meta, err := json.Marshal(u.Meta)
	if err != nil {
		return "", err
	}

	// Set all fields for insert
	bind.Set("meta", string(meta))
	if u.Status != nil && !IsValidUserStatus(*u.Status) {
		return "", auth.ErrBadParameter.Withf("invalid user status %q", *u.Status)
	} else if u.Status != nil {
		bind.Set("status", *u.Status)
	} else {
		bind.Set("status", nil)
	}
	if u.ExpiresAt != nil && u.ExpiresAt.IsZero() {
		bind.Set("expires_at", nil)
	} else {
		bind.Set("expires_at", u.ExpiresAt)
	}
	return bind.Query("user.insert"), nil
}

// Update builds a PATCH-style SET clause from whichever fields are non-zero.
func (u UserMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")
	if name := strings.TrimSpace(u.Name); name != "" {
		bind.Append("patch", "name = "+bind.Set("name", name))
	}
	if email := canonicalizeEmail(u.Email); email != "" {
		if !types.IsEmail(email, nil, &email) {
			return auth.ErrBadParameter.Withf("invalid email address %q", u.Email)
		}
		bind.Append("patch", "email = "+bind.Set("email", canonicalizeEmail(email)))
	}
	if u.Status != nil {
		if !IsValidUserStatus(*u.Status) {
			return auth.ErrBadParameter.Withf("invalid user status %q", *u.Status)
		}
		bind.Append("patch", "status = "+bind.Set("status", *u.Status))
	}
	if u.Meta != nil {
		meta, err := json.Marshal(u.Meta)
		if err != nil {
			return err
		}
		bind.Append("patch", "meta = "+bind.Set("meta", string(meta)))
	}
	if u.ExpiresAt != nil {
		if u.ExpiresAt.IsZero() {
			bind.Append("patch", "expires_at = NULL")
		} else {
			bind.Append("patch", "expires_at = "+bind.Set("expires_at", u.ExpiresAt))
		}
	}
	patch := bind.Join("patch", ", ")
	if patch == "" {
		return auth.ErrBadParameter.With("no fields to update")
	}
	bind.Set("patch", patch)
	return nil
}
