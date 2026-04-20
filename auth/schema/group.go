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
	"database/sql"
	"net/url"
	"strconv"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// CONSTANTS

const (
	// GroupSysAdmin is the built-in administrative group seeded at startup.
	// Its name follows the $name$ convention that marks server-managed groups.
	// Members are granted full access to the management API and CLI.
	GroupSysAdmin = "$admin$"

	// ScopeAuthUserRead grants permission to list and get users.
	ScopeAuthUserRead = "auth:user:read"

	// ScopeAuthUserWrite grants permission to create, update, and delete users.
	ScopeAuthUserWrite = "auth:user:write"

	// ScopeAuthGroupRead grants permission to list and get groups.
	ScopeAuthGroupRead = "auth:group:read"

	// ScopeAuthGroupWrite grants permission to create, update, and delete groups.
	ScopeAuthGroupWrite = "auth:group:write"

	// ScopeAuthKeyRead grants permission to list and get API keys.
	ScopeAuthKeyRead = "auth:key:read"

	// ScopeAuthKeyWrite grants permission to create, update, and delete API keys.
	ScopeAuthKeyWrite = "auth:key:write"
)

var (
	// GroupSysAdminScopes is the fixed set of scopes assigned to GroupSysAdmin at startup.
	GroupSysAdminScopes = []string{
		ScopeAuthUserRead, ScopeAuthUserWrite,
		ScopeAuthGroupRead, ScopeAuthGroupWrite,
		ScopeAuthKeyRead, ScopeAuthKeyWrite,
	}
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type GroupMeta struct {
	Description *string  `json:"description,omitempty"`
	Enabled     *bool    `json:"enabled,omitempty" negatable:""`
	Scopes      []string `json:"scopes,omitempty"`
	Meta        MetaMap  `json:"meta,omitempty"`
}

type GroupInsert struct {
	ID string `json:"id"`
	GroupMeta
}

type Group struct {
	ID string `json:"id" readonly:""`
	GroupMeta
}

// GroupListRequest contains the query parameters for listing groups.
type GroupListRequest struct {
	pg.OffsetLimit
}

// GroupList represents a paginated list of groups.
type GroupList struct {
	pg.OffsetLimit
	Count uint    `json:"count" readonly:""`
	Body  []Group `json:"body,omitempty"`
}

///////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (g GroupMeta) String() string {
	return types.Stringify(g)
}

func (g Group) String() string {
	return types.Stringify(g)
}

func (g GroupList) String() string {
	return types.Stringify(g)
}

func (g GroupInsert) String() string {
	return types.Stringify(g)
}

func (req GroupListRequest) String() string {
	return types.Stringify(req)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - QUERY

func (req GroupListRequest) Query() url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	return values
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

func (group Group) Select(bind *pg.Bind, op pg.Op) (string, error) {
	id, err := normalizeGroupID(group.ID)
	if err != nil {
		return "", err
	}
	bind.Set("id", id)

	switch op {
	case pg.Get:
		return bind.Query("group.select"), nil
	case pg.Update:
		return bind.Query("group.update"), nil
	case pg.Delete:
		return bind.Query("group.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported Group operation %q", op)
	}
}

func (req GroupListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("where", "WHERE group_row.id <> "+bind.Set("system_group", GroupSysAdmin))
	bind.Set("orderby", "ORDER BY group_row.id ASC")
	req.OffsetLimit.Bind(bind, GroupListMax)

	switch op {
	case pg.List:
		return bind.Query("group.list"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported GroupListRequest operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

func (group *Group) Scan(row pg.Row) error {
	var description sql.NullString
	var enabled bool
	if err := row.Scan(&group.ID, &description, &enabled, &group.Scopes, &group.Meta); err != nil {
		return err
	}
	if description.Valid {
		group.Description = types.Ptr(description.String)
	} else {
		group.Description = nil
	}
	group.Enabled = &enabled
	return nil
}

func (list *GroupList) Scan(row pg.Row) error {
	var group Group
	if err := group.Scan(row); err != nil {
		return err
	}
	list.Body = append(list.Body, group)
	return nil
}

func (list *GroupList) ScanCount(row pg.Row) error {
	if err := row.Scan(&list.Count); err != nil {
		return err
	}
	list.Clamp(uint64(list.Count))
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

func (group GroupInsert) Insert(bind *pg.Bind) (string, error) {
	// ID
	if id, err := normalizeGroupID(group.ID); err != nil {
		return "", err
	} else {
		bind.Set("id", id)
	}

	// Description
	if group.Description == nil {
		bind.Set("description", nil)
	} else {
		if description := strings.TrimSpace(*group.Description); description == "" {
			bind.Set("description", nil)
		} else {
			bind.Set("description", description)
		}
	}

	// Enabled
	if group.Enabled == nil {
		bind.Set("enabled", true)
	} else {
		bind.Set("enabled", *group.Enabled)
	}

	// Scopes
	if group.Scopes == nil {
		bind.Set("scopes", []string{})
	} else {
		bind.Set("scopes", normalizeScopes(group.Scopes))
	}

	// Meta
	meta, err := metaInsertExpr(group.Meta.Map())
	if err != nil {
		return "", err
	}
	bind.Set("meta", meta)

	// Return the insert statement
	return bind.Query("group.insert"), nil
}

func (group GroupMeta) Insert(bind *pg.Bind) (string, error) {
	_ = bind
	return "", auth.ErrNotImplemented.With("group meta insert is not supported")
}

func (group GroupMeta) Update(bind *pg.Bind) error {
	bind.Del("patch")

	// Description
	if group.Description != nil {
		if description := strings.TrimSpace(*group.Description); description == "" {
			bind.Append("patch", "description = NULL")
		} else {
			bind.Append("patch", "description = "+bind.Set("description", description))
		}
	}

	// Enabled
	if group.Enabled != nil {
		bind.Append("patch", "enabled = "+bind.Set("enabled", *group.Enabled))
	}

	// Scopes
	if group.Scopes != nil {
		bind.Append("patch", "scopes = "+bind.Set("scopes", normalizeScopes(group.Scopes)))
	}

	// Meta
	if group.Meta != nil {
		expr, err := metaPatchExpr(bind, "meta", "meta", group.Meta.Map())
		if err != nil {
			return err
		}
		bind.Append("patch", "meta = "+expr)
	}

	// Patch
	if patch := bind.Join("patch", ", "); patch == "" {
		return auth.ErrBadParameter.With("no fields to update")
	} else {
		bind.Set("patch", patch)
	}

	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// IsSystemGroup reports whether id is a server-managed group.
// System groups are identified by the $name$ naming convention and are
// seeded at startup; they cannot be created, updated, or deleted via the API.
func IsSystemGroup(id string) bool {
	return len(id) > 2 && id[0] == '$' && id[len(id)-1] == '$'
}

func normalizeGroupID(id string) (string, error) {
	if id = strings.TrimSpace(id); id == "" {
		return "", auth.ErrBadParameter.With("group id is required")
	} else if !types.IsIdentifier(id) {
		return "", auth.ErrBadParameter.Withf("invalid group id %q", id)
	} else {
		return id, nil
	}
}
