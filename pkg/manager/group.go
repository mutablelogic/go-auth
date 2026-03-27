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

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) CreateGroup(ctx context.Context, insert schema.GroupInsert) (_ *schema.Group, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.CreateGroup", attribute.String("insert", insert.String()))
	defer func() { endSpan(err) }()

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
