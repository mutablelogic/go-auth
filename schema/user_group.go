package schema

import (
	// Packages
	auth "github.com/djthorpe/go-auth"
	pg "github.com/mutablelogic/go-pg"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserGroupListRequest struct {
	User UserID
}

type UserGroupInsert struct {
	User   UserID
	Groups []string
}

type UserGroupList []string

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SELECTOR

func (req UserGroupListRequest) Select(bind *pg.Bind, op pg.Op) (string, error) {
	bind.Set("user", req.User)
	switch op {
	case pg.List:
		return bind.Query("user_group.list"), nil
	case pg.Delete:
		return bind.Query("user_group.delete"), nil
	default:
		return "", auth.ErrNotImplemented.Withf("unsupported UserGroupListRequest operation %q", op)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - WRITER

func (insert UserGroupInsert) Insert(bind *pg.Bind) (string, error) {
	bind.Set("user", insert.User)
	bind.Set("groups", insert.Groups)
	return bind.Query("user_group.insert"), nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - READER

func (list *UserGroupList) Scan(row pg.Row) error {
	var group string
	if err := row.Scan(&group); err != nil {
		return err
	}
	*list = append(*list, group)
	return nil
}
