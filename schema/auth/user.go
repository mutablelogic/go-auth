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
	"slices"
	"strconv"
	"strings"
	"time"

	// Packages
	auth "github.com/djthorpe/go-auth"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
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
	Name      string      `json:"name,omitempty"`
	Email     string      `json:"email,omitempty"`
	Groups    []string    `json:"groups,omitempty"`
	Status    *UserStatus `json:"status,omitempty" enum:"new,active,inactive,suspended,deleted"`
	Meta      MetaMap     `json:"meta,omitempty"`
	ExpiresAt *time.Time  `json:"expires_at,omitzero" format:"date-time"`
}

// User represents a user account in the system. It contains both
// immutable and mutable fields.
type User struct {
	ID             UserID         `json:"id" format:"uuid" readonly:""`
	CreatedAt      time.Time      `json:"created_at" format:"date-time" readonly:""`
	ModifiedAt     *time.Time     `json:"modified_at,omitempty" format:"date-time" readonly:""`
	Claims         map[string]any `json:"claims,omitempty" readonly:""`
	EffectiveMeta  MetaMap        `json:"effective_meta,omitempty" readonly:""`
	DisabledGroups []string       `json:"disabled_groups,omitempty" readonly:""`
	Scopes         []string       `json:"scopes,omitempty" readonly:""`
	UserMeta
}

// UserListRequest contains the query parameters for listing users.
type UserListRequest struct {
	pg.OffsetLimit
	Email  string       `json:"email,omitempty"`
	Status []UserStatus `json:"status,omitempty" enum:"new,active,inactive,suspended,deleted"`
}

// UserList represents a paginated list of users.
type UserList struct {
	pg.OffsetLimit
	Count uint   `json:"count" readonly:""`
	Body  []User `json:"body,omitempty"`
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

// UserIDFromString parses a string into a UserID, which is a UUID.
func UserIDFromString(s string) (UserID, error) {
	if uid, err := uuid.Parse(strings.Trim(s, `"`)); err != nil {
		return UserID(uuid.Nil), err
	} else if uid == uuid.Nil {
		return UserID(uuid.Nil), auth.ErrBadParameter.With("id cannot be nil")
	} else {
		return UserID(uid), nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (id UserID) String() string {
	return uuid.UUID(id).String()
}

func (id UserID) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

func (u UserList) String() string {
	return types.Stringify(u)
}

func (u UserListRequest) String() string {
	return types.Stringify(u)
}

func (u UserListRequest) RedactedString() string {
	r := u
	if r.Email != "" {
		r.Email = "[redacted]"
	}
	return types.Stringify(r)
}

func (u UserMeta) String() string {
	return types.Stringify(u)
}

func (u UserMeta) RedactedString() string {
	r := u
	if r.Name != "" {
		r.Name = "[redacted]"
	}
	if r.Email != "" {
		r.Email = "[redacted]"
	}
	return types.Stringify(r)
}

func (u User) String() string {
	return types.Stringify(u)
}

func (u User) RedactedString() string {
	r := u
	if r.Name != "" {
		r.Name = "[redacted]"
	}
	if r.Email != "" {
		r.Email = "[redacted]"
	}
	return types.Stringify(r)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - UUID

func (id UserID) MarshalJSON() ([]byte, error) {
	return json.Marshal(uuid.UUID(id))
}

func (id *UserID) UnmarshalText(text []byte) error {
	uid, err := UserIDFromString(string(text))
	if err != nil {
		return err
	}
	*id = uid
	return nil
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
// PUBLIC METHODS - USER

func (u User) HasScope(scope string) bool {
	return slices.Contains(u.Scopes, strings.TrimSpace(scope))
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - QUERY

func (req UserListRequest) Query() url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	if req.Email != "" {
		values.Set("email", req.Email)
	}
	for _, status := range req.Status {
		values.Add("status", string(status))
	}
	return values
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

func (req UserListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Del("where")

	if email := canonicalizeEmail(req.Email); email != "" {
		if !types.IsEmail(email, nil, &email) {
			return "", auth.ErrBadParameter.Withf("invalid email address %q", req.Email)
		}
		bind.Append("where", "user_row.email = "+bind.Set("email", email))
	}
	if len(req.Status) > 0 {
		statuses := make([]string, 0, len(req.Status))
		for _, status := range req.Status {
			if !IsValidUserStatus(status) {
				return "", auth.ErrBadParameter.Withf("invalid user status %q", status)
			}
			statuses = append(statuses, string(status))
		}
		bind.Append("where", "user_row.status = ANY("+bind.Set("status", statuses)+")")
	}
	if where := bind.Join("where", " AND "); where == "" {
		bind.Set("where", "")
	} else {
		bind.Set("where", "WHERE "+where)
	}
	bind.Set("orderby", "ORDER BY user_row.email ASC, user_row.id ASC")

	// Offset, Limit and Order by
	req.OffsetLimit.Bind(bind, UserListMax)

	switch op {
	case pg.List:
		return bind.Query("user.list"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported UserListRequest operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

func (u *User) Scan(row pg.Row) error {
	return row.Scan(
		&u.ID,
		&u.Name,
		&u.Email,
		&u.Meta,
		&u.EffectiveMeta,
		&u.Status,
		&u.CreatedAt,
		&u.ExpiresAt,
		&u.ModifiedAt,
		&u.Claims,
		&u.Groups,
		&u.DisabledGroups,
		&u.Scopes,
	)
}

func (list *UserList) Scan(row pg.Row) error {
	var user User
	if err := user.Scan(row); err != nil {
		return err
	}
	list.Body = append(list.Body, user)
	return nil
}

func (list *UserList) ScanCount(row pg.Row) error {
	if err := row.Scan(&list.Count); err != nil {
		return err
	}
	list.Clamp(uint64(list.Count))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

// Insert binds all UserMeta fields for an INSERT and returns the named query.
func (u UserMeta) Insert(bind *pg.Bind) (string, error) {
	// Fix meta
	if u.Meta == nil {
		u.Meta = MetaMap{}
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

	meta, err := metaInsertExpr(u.Meta.Map())
	if err != nil {
		return "", err
	}

	// Set all fields for insert
	bind.Set("meta", meta)
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
		expr, err := metaPatchExpr(bind, "meta", "meta", u.Meta.Map())
		if err != nil {
			return err
		}
		bind.Append("patch", "meta = "+expr)
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
