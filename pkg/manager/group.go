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
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// groupScopeSelector is an internal pg selector for the group.add_scope and
// group.remove_scope named queries. It binds id and scope then returns the
// named query regardless of the pg.Op passed by the pool.
type groupScopeSelector struct {
	id    string
	scope string
	query string // "group.add_scope" or "group.remove_scope"
}

func (g groupScopeSelector) Select(bind *pg.Bind, _ pg.Op) (string, error) {
	bind.Set("id", g.id)
	bind.Set("scope", g.scope)
	return bind.Query(g.query), nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) CreateGroup(ctx context.Context, insert schema.GroupInsert) (_ *schema.Group, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.CreateGroup", attribute.String("insert", insert.String()))
	defer func() { endSpan(err) }()

	if schema.IsSystemGroup(insert.ID) {
		err = auth.ErrForbidden.Withf("group %q is server-managed and cannot be created via the API", insert.ID)
		return nil, err
	}
	var result schema.Group
	if err = m.PoolConn.Insert(ctx, &result, insert); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) GetGroup(ctx context.Context, name string) (_ *schema.Group, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.GetGroup", attribute.String("name", name))
	defer func() { endSpan(err) }()

	var result schema.Group
	if err = m.PoolConn.Get(ctx, &result, schema.Group{ID: name}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) UpdateGroup(ctx context.Context, name string, meta schema.GroupMeta) (_ *schema.Group, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.UpdateGroup",
		attribute.String("name", name),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	if schema.IsSystemGroup(name) {
		err = auth.ErrForbidden.Withf("group %q is server-managed and cannot be modified via the API", name)
		return nil, err
	}
	var result schema.Group
	if err = m.PoolConn.Update(ctx, &result, schema.Group{ID: name}, meta); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) DeleteGroup(ctx context.Context, name string) (_ *schema.Group, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.DeleteGroup", attribute.String("name", name))
	defer func() { endSpan(err) }()

	if schema.IsSystemGroup(name) {
		err = auth.ErrForbidden.Withf("group %q is server-managed and cannot be deleted via the API", name)
		return nil, err
	}
	var result schema.Group
	if err = m.PoolConn.Delete(ctx, &result, schema.Group{ID: name}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) ListGroups(ctx context.Context, req schema.GroupListRequest) (_ *schema.GroupList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.ListGroups", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := schema.GroupList{OffsetLimit: req.OffsetLimit}
	if err = m.PoolConn.List(ctx, &result, req); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

// AddGroupScope appends scope to the named group's scope list if not already
// present. The operation is idempotent and atomic. It may be called on system
// groups; the IsSystemGroup guard only applies to the public Update/Delete
// methods.
func (m *Manager) AddGroupScope(ctx context.Context, name, scope string) (_ *schema.Group, err error) {
	scope = strings.TrimSpace(scope)
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.AddGroupScope",
		attribute.String("name", name),
		attribute.String("scope", scope),
	)
	defer func() { endSpan(err) }()

	if scope == "" {
		err = auth.ErrBadParameter.With("scope is required")
		return nil, err
	}
	var result schema.Group
	sel := groupScopeSelector{id: name, scope: scope, query: "group.add_scope"}
	if err = m.PoolConn.Get(ctx, &result, sel); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

// RemoveGroupScope removes scope from the named group's scope list. The
// operation is idempotent and atomic.
func (m *Manager) RemoveGroupScope(ctx context.Context, name, scope string) (_ *schema.Group, err error) {
	scope = strings.TrimSpace(scope)
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.RemoveGroupScope",
		attribute.String("name", name),
		attribute.String("scope", scope),
	)
	defer func() { endSpan(err) }()

	if scope == "" {
		err = auth.ErrBadParameter.With("scope is required")
		return nil, err
	}
	var result schema.Group
	sel := groupScopeSelector{id: name, scope: scope, query: "group.remove_scope"}
	if err = m.PoolConn.Get(ctx, &result, sel); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}
