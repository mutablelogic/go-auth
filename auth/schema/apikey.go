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

// KeyMeta contains the writable fields for an API key.
type KeyMeta struct {
	Name      string     `json:"name,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty" format:"date-time"`
}

// Key represents a stored API key row plus the generated plaintext token.
type Key struct {
	User       UserID      `json:"user" format:"uuid"`
	CreatedAt  time.Time   `json:"created_at" format:"date-time" readonly:""`
	ModifiedAt time.Time   `json:"modified_at" format:"date-time" readonly:""`
	Status     *UserStatus `json:"status,omitempty" readonly:"" enum:"new,active,inactive,suspended,deleted"`
	Token      string      `json:"token,omitempty" readonly:""`
	KeyMeta
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (k KeyMeta) String() string {
	return types.Stringify(k)
}

func (k Key) String() string {
	return types.Stringify(k)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

// Scan reads a full API key row into the receiver.
// Expected column order: user, name, created_at, modified_at,
// expires_at, status, token.
func (k *Key) Scan(row pg.Row) error {
	return row.Scan(
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

func (k KeyMeta) Update(_ *pg.Bind) error {
	return auth.ErrNotImplemented.With("api key update is not supported")
}
