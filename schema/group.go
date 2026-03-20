package schema

import (
	"database/sql"
	"net/url"
	"strconv"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type GroupMeta struct {
	Description *string        `json:"description,omitempty"`
	Enabled     *bool          `json:"enabled,omitempty"`
	Scopes      []string       `json:"scopes,omitempty"`
	Meta        map[string]any `json:"meta,omitempty"`
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
	bind.Set("where", "")
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
		bind.Set("scopes", group.Scopes)
	}

	// Meta
	meta, err := metaInsertExpr(group.Meta)
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
		bind.Append("patch", "scopes = "+bind.Set("scopes", group.Scopes))
	}

	// Meta
	if group.Meta != nil {
		expr, err := metaPatchExpr(bind, "meta", "meta", group.Meta)
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

func normalizeGroupID(id string) (string, error) {
	if id = strings.TrimSpace(id); id == "" {
		return "", auth.ErrBadParameter.With("group id is required")
	} else if !types.IsIdentifier(id) {
		return "", auth.ErrBadParameter.Withf("invalid group id %q", id)
	} else {
		return id, nil
	}
}
