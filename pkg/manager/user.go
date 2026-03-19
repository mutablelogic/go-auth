package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CreateUser inserts a new user row. If identity is non-nil it is inserted in
// the same transaction and the returned User is re-fetched so that Email and
// Claims reflect the new identity row.
func (m *Manager) CreateUser(ctx context.Context, meta schema.UserMeta, identity *schema.IdentityInsert) (*schema.User, error) {
	var user schema.User

	// Simple case: no identity, single insert.
	if identity == nil {
		if err := m.PoolConn.Insert(ctx, &user, meta); err != nil {
			return nil, dbErr(err)
		}
		return types.Ptr(user), nil
	}

	// With identity: both inserts must succeed together.
	if err := m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		if err := conn.Insert(ctx, &user, meta); err != nil {
			return err
		} else {
			return conn.With("user", user.ID).Insert(ctx, nil, types.Value(identity))
		}
	}); err != nil {
		return nil, dbErr(err)
	}

	// Re-fetch so that Email/Claims are populated from the new identity row.
	return m.GetUser(ctx, uuid.UUID(user.ID))
}

func (m *Manager) GetUser(ctx context.Context, user uuid.UUID) (*schema.User, error) {
	var result schema.User
	if err := m.PoolConn.Get(ctx, &result, schema.UserID(user)); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) UpdateUser(ctx context.Context, user uuid.UUID, meta schema.UserMeta) (*schema.User, error) {
	var result schema.User
	if err := m.PoolConn.Update(ctx, &result, schema.UserID(user), meta); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) DeleteUser(ctx context.Context, user uuid.UUID) (*schema.User, error) {
	var result schema.User
	if err := m.PoolConn.Delete(ctx, &result, schema.UserID(user)); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}
