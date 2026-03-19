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

// SessionID is a unique identifier for a session.
type SessionID uuid.UUID

// SessionMeta contains the mutable fields for a session.
type SessionMeta struct {
	ExpiresIn *time.Duration `json:"expires_in,omitempty"`
	RevokedAt *time.Time     `json:"revoked_at,omitempty"`
}

// SessionInsert contains the fields required to create a new session.
type SessionInsert struct {
	User      UserID         `json:"user"`
	ExpiresIn *time.Duration `json:"expires_in"`
}

// Session represents a stored session row.
type Session struct {
	ID        SessionID `json:"id"`
	User      UserID    `json:"user"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	SessionMeta
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - UUID

func (id SessionID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *SessionID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	} else if uid, err := uuid.Parse(strings.Trim(s, `"`)); err != nil {
		return err
	} else if uid == uuid.Nil {
		return auth.ErrBadParameter.With("id cannot be nil")
	} else {
		*id = SessionID(uid)
	}

	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

// Select binds the session ID and returns the appropriate named query for the
// given operation (Get, Update or Delete).
func (id SessionID) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(id))
	switch op {
	case pg.Get:
		return bind.Query("session.select"), nil
	case pg.Update:
		return bind.Query("session.update"), nil
	case pg.Delete:
		return bind.Query("session.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported SessionID operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

// Scan reads a full session row into the receiver.
// Expected column order: id, user, expires_at, created_at, revoked_at.
func (s *Session) Scan(row pg.Row) error {
	return row.Scan(
		&s.ID,
		&s.User,
		&s.ExpiresAt,
		&s.CreatedAt,
		&s.RevokedAt,
	)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

// Insert binds all required session fields for an INSERT and returns the named query.
func (s SessionInsert) Insert(bind *pg.Bind) (string, error) {
	if s.User == UserID(uuid.Nil) {
		return "", auth.ErrBadParameter.With("user is required")
	}
	if s.ExpiresIn == nil {
		return "", auth.ErrBadParameter.With("expires_in is required")
	}
	if *s.ExpiresIn <= 0 {
		return "", auth.ErrBadParameter.With("expires_in must be greater than zero")
	}
	bind.Set("user", s.User)
	bind.Set("expires_in", s.ExpiresIn)
	return bind.Query("session.insert"), nil
}

// Update builds a PATCH-style SET clause from whichever fields are non-zero.
func (s SessionMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")
	if s.ExpiresIn != nil {
		if *s.ExpiresIn <= 0 {
			return auth.ErrBadParameter.With("expires_in must be greater than zero")
		}
		bind.Append("patch", "expires_at = NOW() + "+bind.Set("expires_in", s.ExpiresIn))
	}
	if s.RevokedAt != nil {
		if s.RevokedAt.IsZero() {
			bind.Append("patch", "revoked_at = NULL")
		} else {
			bind.Append("patch", "revoked_at = "+bind.Set("revoked_at", s.RevokedAt))
		}
	}
	if patch := bind.Join("patch", ", "); patch == "" {
		return auth.ErrBadParameter.With("no fields to update")
	} else {
		bind.Set("patch", patch)
	}
	return nil
}
