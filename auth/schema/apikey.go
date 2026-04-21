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
	"encoding/json"
	"net/url"
	"strconv"
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

// KeyListRequest contains the query parameters for listing API keys.
type KeyListRequest struct {
	pg.OffsetLimit
	User    *UserID `form:"user" json:"user,omitempty" query:"user" jsonschema:"Optional filter to list API keys belonging to a specific user account." format:"uuid" example:"123e4567-e89b-12d3-a456-426614174000"`
	Expired *bool   `form:"expired" json:"expired,omitempty" query:"expired" jsonschema:"Optional filter to list only expired or non-expired API keys. When true, only keys that are currently expired are returned; when false, only keys that are not currently expired are returned." example:"false"`
}

// KeyList represents a paginated list of API keys.
type KeyList struct {
	KeyListRequest
	Count uint  `json:"count" readonly:""`
	Body  []Key `json:"body,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func KeyIDFromString(s string) (KeyID, error) {
	if uid, err := uuid.Parse(strings.Trim(s, `"`)); err != nil {
		return KeyID(uuid.Nil), err
	} else if uid == uuid.Nil {
		return KeyID(uuid.Nil), auth.ErrBadParameter.With("id cannot be nil")
	} else {
		return KeyID(uid), nil
	}
}

func (k KeyID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(k))
}

func (k KeyID) String() string {
	return uuid.UUID(k).String()
}

func (k KeyID) MarshalText() ([]byte, error) {
	return []byte(k.String()), nil
}

func (k *KeyID) UnmarshalText(text []byte) error {
	id, err := KeyIDFromString(string(text))
	if err != nil {
		return err
	}
	*k = id
	return nil
}

func (k *KeyID) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	} else if id, err := KeyIDFromString(s); err != nil {
		return err
	} else {
		*k = id
	}
	return nil
}

func (k KeyMeta) String() string {
	return types.Stringify(k)
}

func (k Key) String() string {
	return types.Stringify(k)
}

func (k KeyList) String() string {
	return types.Stringify(k)
}

func (req KeyListRequest) String() string {
	return types.Stringify(req)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - QUERY

func (req KeyListRequest) Query() url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	if req.User != nil {
		values.Set("user", req.User.String())
	}
	if req.Expired != nil {
		values.Set("expired", strconv.FormatBool(types.Value(req.Expired)))
	}
	return values
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

func (list *KeyList) Scan(row pg.Row) error {
	var key Key
	if err := key.Scan(row); err != nil {
		return err
	}
	list.Body = append(list.Body, key)
	return nil
}

func (list *KeyList) ScanCount(row pg.Row) error {
	if err := row.Scan(&list.Count); err != nil {
		return err
	}
	list.Clamp(uint64(list.Count))
	return nil
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

func (req KeyListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Del("where")
	if req.User != nil {
		bind.Append("where", `apikey."user" = `+bind.Set("user", uuid.UUID(*req.User)))
	}
	if req.Expired != nil {
		if types.Value(req.Expired) {
			bind.Append("where", `(
				CASE
					WHEN user_row.expires_at IS NULL THEN apikey.expires_at
					WHEN apikey.expires_at IS NULL THEN user_row.expires_at
					ELSE LEAST(apikey.expires_at, user_row.expires_at)
				END
			) < NOW()`)
		} else {
			bind.Append("where", `((
				CASE
					WHEN user_row.expires_at IS NULL THEN apikey.expires_at
					WHEN apikey.expires_at IS NULL THEN user_row.expires_at
					ELSE LEAST(apikey.expires_at, user_row.expires_at)
				END
			) IS NULL OR (
				CASE
					WHEN user_row.expires_at IS NULL THEN apikey.expires_at
					WHEN apikey.expires_at IS NULL THEN user_row.expires_at
					ELSE LEAST(apikey.expires_at, user_row.expires_at)
				END
			) >= NOW())`)
		}
	}
	if where := bind.Join("where", " AND "); where == "" {
		bind.Set("where", "")
	} else {
		bind.Set("where", "WHERE "+where)
	}
	bind.Set("orderby", `ORDER BY apikey.created_at DESC, apikey.id ASC`)
	req.OffsetLimit.Bind(bind, KeyListMax)

	switch op {
	case pg.List:
		return bind.Query("apikey.list"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported KeyListRequest operation %q", op)
	}
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
