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
	uuid "github.com/google/uuid"
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const defaultKeyDigestAlgorithm = "sha256"

///////////////////////////////////////////////////////////////////////////////
// TYPES

// KeyID is a unique identifier for an API key.
type KeyID uuid.UUID

// KeyToken selects API key rows by plaintext token.
type KeyToken struct {
	Token string
	Query string
}

// KeySelector selects an API key row by ID and optionally scopes it to a user.
type KeySelector struct {
	ID    KeyID
	User  *UserID
	Query string
}

// KeyMeta contains the writable fields for an API key.
type KeyMeta struct {
	Name      string     `json:"name,omitempty" jsonschema:"Human-readable label for the API key. Names must be unique per user account." example:"deploy-bot"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" jsonschema:"Optional absolute expiry for the API key. When both the user and the key have expiries, the effective expiry is the earlier of the two." format:"date-time" example:"2026-12-31T23:59:59Z"`
}

// Key represents a stored API key row plus the generated plaintext token.
type Key struct {
	ID         KeyID       `json:"id" jsonschema:"Stable identifier for the stored API key row." format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000" readonly:""`
	User       UserID      `json:"user" jsonschema:"Identifier of the local user account that owns the API key." format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000"`
	CreatedAt  time.Time   `json:"created_at" jsonschema:"Timestamp when the API key row was created." format:"date-time" example:"2026-04-20T18:00:00Z" readonly:""`
	ModifiedAt time.Time   `json:"modified_at" jsonschema:"Timestamp when the API key row was last modified." format:"date-time" example:"2026-04-20T18:05:00Z" readonly:""`
	Status     *UserStatus `json:"status,omitempty" jsonschema:"Current status of the owning user account. This is included to show whether the key belongs to an active, inactive, suspended, or deleted user." readonly:"" enum:"new,active,inactive,suspended,deleted" example:"active"`
	Token      string      `json:"token,omitempty" jsonschema:"Plaintext API token. This is only returned when the token is first created; subsequent lookups return metadata only." example:"test_4f7c0f6f4c7a2f80f8bb5c5f2f8b4e9a8a7d6c5b4e3f2a1d0c9b8a7f6e5d4c3" readonly:""`
	KeyMeta
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (k KeyID) String() string {
	return uuid.UUID(k).String()
}

func (k KeyMeta) String() string {
	return types.Stringify(k)
}

func (k Key) String() string {
	return types.Stringify(k)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

// Scan reads a full API key row into the receiver.
// Expected column order: id, user, name, created_at, modified_at,
// expires_at, status, token.
func (k *Key) Scan(row pg.Row) error {
	return row.Scan(
		&k.ID,
		&k.User,
		&k.Name,
		&k.CreatedAt,
		&k.ModifiedAt,
		&k.ExpiresAt,
		&k.Status,
		&k.Token,
	)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

func (id KeyID) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(id))
	switch op {
	case pg.Get:
		return bind.Query("apikey.get"), nil
	case pg.Update:
		return bind.Query("apikey.update"), nil
	case pg.Delete:
		return bind.Query("apikey.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported KeyID operation %q", op)
	}
}

func (k KeySelector) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("id", uuid.UUID(k.ID))
	if k.User == nil {
		bind.Set("user", nil)
	} else {
		bind.Set("user", uuid.UUID(*k.User))
	}
	switch op {
	case pg.Get, pg.Update, pg.Delete:
		return bind.Query(k.Query), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported KeySelector operation %q", op)
	}
}

func (k KeyToken) Select(bind *pg.Bind, op pg.Op) (string, error) {
	if op != pg.Get {
		return "", auth.ErrNotImplemented.Withf("unsupported KeyToken operation %q", op)
	}
	if token := strings.TrimSpace(k.Token); token == "" {
		return "", auth.ErrBadParameter.With("token is required")
	} else {
		bind.Set("token", token)
	}
	bind.Set("algorithm", defaultKeyDigestAlgorithm)
	return bind.Query(k.Query), nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

func (k KeyMeta) Insert(bind *pg.Bind) (string, error) {
	// User
	if user, ok := bind.Get("user").(UserID); !ok || user == UserID(uuid.Nil) {
		return "", auth.ErrBadParameter.With("user is required")
	}

	// API Key name
	if name := strings.TrimSpace(k.Name); name == "" {
		return "", auth.ErrBadParameter.With("name is required")
	} else {
		bind.Set("name", name)
	}

	// Expires at
	if k.ExpiresAt != nil && k.ExpiresAt.IsZero() {
		bind.Set("expires_at", nil)
	} else {
		bind.Set("expires_at", k.ExpiresAt)
	}

	// Hashing algorithm
	bind.Set("algorithm", defaultKeyDigestAlgorithm)

	// Return the insert query
	return bind.Query("apikey.insert"), nil
}

func (k KeyMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")
	if name := strings.TrimSpace(k.Name); name != "" {
		bind.Append("patch", "name = "+bind.Set("name", name))
	}
	if k.ExpiresAt != nil {
		if k.ExpiresAt.IsZero() {
			bind.Append("patch", "expires_at = NULL")
		} else {
			bind.Append("patch", "expires_at = "+bind.Set("expires_at", k.ExpiresAt))
		}
	}
	if patch := bind.Join("patch", ", "); patch == "" {
		return auth.ErrBadParameter.With("no fields to update")
	} else {
		bind.Set("patch", patch)
	}
	return nil
}
