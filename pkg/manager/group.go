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
