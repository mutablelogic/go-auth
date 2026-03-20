package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) CreateGroup(ctx context.Context, insert schema.GroupInsert) (*schema.Group, error) {
	var result schema.Group
	if err := m.PoolConn.Insert(ctx, &result, insert); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) GetGroup(ctx context.Context, name string) (*schema.Group, error) {
	var result schema.Group
	if err := m.PoolConn.Get(ctx, &result, schema.Group{ID: name}); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) UpdateGroup(ctx context.Context, name string, meta schema.GroupMeta) (*schema.Group, error) {
	var result schema.Group
	if err := m.PoolConn.Update(ctx, &result, schema.Group{ID: name}, meta); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) DeleteGroup(ctx context.Context, name string) (*schema.Group, error) {
	var result schema.Group
	if err := m.PoolConn.Delete(ctx, &result, schema.Group{ID: name}); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) ListGroups(ctx context.Context, req schema.GroupListRequest) (*schema.GroupList, error) {
	result := schema.GroupList{OffsetLimit: req.OffsetLimit}
	if err := m.PoolConn.List(ctx, &result, req); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}
