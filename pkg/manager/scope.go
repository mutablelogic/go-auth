package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) ListScopes(ctx context.Context, req schema.ScopeListRequest) (*schema.ScopeList, error) {
	result := schema.ScopeList{OffsetLimit: req.OffsetLimit}
	if err := m.PoolConn.List(ctx, &result, req); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}
