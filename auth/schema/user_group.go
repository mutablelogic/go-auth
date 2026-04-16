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
	// Packages
	auth "github.com/mutablelogic/go-auth"
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

func (insert UserGroupInsert) Update(_ *pg.Bind) error {
	return auth.ErrNotImplemented.With("user group insert update is not supported")
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
