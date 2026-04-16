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

package manager

import (
	"context"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/schema/auth"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CreateUser inserts a new user row. If identity is non-nil it is inserted in
// the same transaction and the returned User is re-fetched so that Email and
// Claims reflect the new identity row.
func (m *Manager) CreateUser(ctx context.Context, meta schema.UserMeta, identity *schema.IdentityInsert) (_ *schema.User, err error) {
	attrs := []attribute.KeyValue{attribute.String("meta", meta.RedactedString())}
	if identity != nil {
		attrs = append(attrs, attribute.String("identity", identity.RedactedString()))
	}
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.CreateUser", attrs...)
	defer func() { endSpan(err) }()

	var user schema.User
	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		rowMeta := meta
		rowMeta.Groups = nil

		if err := conn.Insert(ctx, &user, rowMeta); err != nil {
			return err
		}
		if err := replaceUserGroups(ctx, conn, user.ID, meta.Groups); err != nil {
			return err
		}
		if identity != nil {
			return conn.With("user", user.ID).Insert(ctx, nil, types.Value(identity))
		}
		return nil
	}); err != nil {
		err = dbErr(err)
		return nil, err
	}

	// Re-fetch so that Email/Claims/Groups/Scopes reflect any transactional work.
	return m.GetUser(ctx, user.ID)
}

func (m *Manager) GetUser(ctx context.Context, user schema.UserID) (_ *schema.User, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.GetUser", attribute.String("user", user.String()))
	defer func() { endSpan(err) }()

	var result schema.User
	if err = m.PoolConn.Get(ctx, &result, user); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) UpdateUser(ctx context.Context, user schema.UserID, meta schema.UserMeta) (_ *schema.User, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.UpdateUser",
		attribute.String("user", user.String()),
		attribute.String("meta", meta.RedactedString()),
	)
	defer func() { endSpan(err) }()

	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		rowMeta := meta
		rowMeta.Groups = nil

		hasRowPatch := strings.TrimSpace(rowMeta.Name) != "" || strings.TrimSpace(rowMeta.Email) != "" || rowMeta.Status != nil || rowMeta.Meta != nil || rowMeta.ExpiresAt != nil
		hasGroups := meta.Groups != nil
		if !hasRowPatch && !hasGroups {
			return auth.ErrBadParameter.With("no fields to update")
		}

		var userRow schema.User
		if hasRowPatch {
			if err := conn.Update(ctx, &userRow, user, rowMeta); err != nil {
				return err
			}
		} else {
			if err := conn.Get(ctx, &userRow, user); err != nil {
				return err
			}
		}

		if hasGroups {
			if err := replaceUserGroups(ctx, conn, user, meta.Groups); err != nil {
				return err
			}
		}

		return nil
	}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return m.GetUser(ctx, user)
}

func (m *Manager) AddUserGroups(ctx context.Context, user schema.UserID, groups []string) (_ *schema.User, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.AddUserGroups",
		attribute.String("user", user.String()),
		attribute.String("groups", types.Stringify(groups)),
	)
	defer func() { endSpan(err) }()

	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		var existing schema.User
		if err := conn.Get(ctx, &existing, user); err != nil {
			return err
		}

		current, err := listUserGroups(ctx, conn, user)
		if err != nil {
			return err
		}
		additions, err := normalizeUserGroups(groups)
		if err != nil {
			return err
		}

		merged := append([]string{}, current...)
		seen := make(map[string]struct{}, len(current))
		for _, group := range current {
			seen[group] = struct{}{}
		}
		for _, group := range additions {
			if _, exists := seen[group]; exists {
				continue
			}
			seen[group] = struct{}{}
			merged = append(merged, group)
		}

		return replaceUserGroups(ctx, conn, user, merged)
	}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return m.GetUser(ctx, user)
}

func (m *Manager) RemoveUserGroups(ctx context.Context, user schema.UserID, groups []string) (_ *schema.User, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.RemoveUserGroups",
		attribute.String("user", user.String()),
		attribute.String("groups", types.Stringify(groups)),
	)
	defer func() { endSpan(err) }()

	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		var existing schema.User
		if err := conn.Get(ctx, &existing, user); err != nil {
			return err
		}

		current, err := listUserGroups(ctx, conn, user)
		if err != nil {
			return err
		}
		removals, err := normalizeUserGroups(groups)
		if err != nil {
			return err
		}

		removeSet := make(map[string]struct{}, len(removals))
		for _, group := range removals {
			removeSet[group] = struct{}{}
		}

		filtered := make([]string, 0, len(current))
		for _, group := range current {
			if _, remove := removeSet[group]; remove {
				continue
			}
			filtered = append(filtered, group)
		}

		return replaceUserGroups(ctx, conn, user, filtered)
	}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return m.GetUser(ctx, user)
}

func (m *Manager) DeleteUser(ctx context.Context, user schema.UserID) (_ *schema.User, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.DeleteUser", attribute.String("user", user.String()))
	defer func() { endSpan(err) }()

	var result schema.User
	if err = m.PoolConn.Delete(ctx, &result, user); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) ListUsers(ctx context.Context, req schema.UserListRequest) (_ *schema.UserList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.ListUsers", attribute.String("request", req.RedactedString()))
	defer func() { endSpan(err) }()

	result := schema.UserList{OffsetLimit: req.OffsetLimit}
	if err = m.PoolConn.List(ctx, &result, req); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listUserGroups(ctx context.Context, conn pg.Conn, user schema.UserID) ([]string, error) {
	var result schema.UserGroupList
	if err := conn.List(ctx, &result, schema.UserGroupListRequest{User: user}); err != nil {
		return nil, err
	}
	return []string(result), nil
}

func replaceUserGroups(ctx context.Context, conn pg.Conn, user schema.UserID, groups []string) error {
	normalized, err := normalizeUserGroups(groups)
	if err != nil {
		return err
	}

	if err := conn.Delete(ctx, nil, schema.UserGroupListRequest{User: user}); err != nil {
		return err
	}

	if len(normalized) == 0 {
		return nil
	}

	return conn.Insert(ctx, nil, schema.UserGroupInsert{User: user, Groups: normalized})
}

func normalizeUserGroups(groups []string) ([]string, error) {
	if groups == nil {
		return nil, nil
	}

	result := make([]string, 0, len(groups))
	seen := make(map[string]struct{}, len(groups))
	for _, group := range groups {
		group = strings.TrimSpace(group)
		if group == "" {
			continue
		}
		if !types.IsIdentifier(group) {
			return nil, auth.ErrBadParameter.Withf("invalid group id %q", group)
		}
		if _, exists := seen[group]; exists {
			continue
		}
		seen[group] = struct{}{}
		result = append(result, group)
	}
	return result, nil
}
