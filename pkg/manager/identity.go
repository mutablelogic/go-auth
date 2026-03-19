package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CreateIdentity inserts a new identity row for an existing user.
func (m *Manager) CreateIdentity(ctx context.Context, user uuid.UUID, identity schema.IdentityInsert) (*schema.Identity, error) {
	var result schema.Identity
	if err := m.PoolConn.With(
		"user", schema.UserID(user),
	).Insert(ctx, &result, types.Value(&identity)); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

// GetIdentity retrieves a single identity by its (provider, sub) primary key.
func (m *Manager) GetIdentity(ctx context.Context, provider, sub string) (*schema.Identity, error) {
	var identity schema.Identity
	if err := m.PoolConn.Get(ctx, &identity, schema.IdentityKey{Provider: provider, Sub: sub}); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(identity), nil
}

// UpdateIdentity refreshes the mutable fields (email, claims) on an existing
// identity row identified by (provider, sub). modified_at is always updated.
func (m *Manager) UpdateIdentity(ctx context.Context, provider, sub string, meta schema.IdentityMeta) (*schema.Identity, error) {
	var identity schema.Identity
	if err := m.PoolConn.Update(ctx, &identity, schema.IdentityKey{Provider: provider, Sub: sub}, meta); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(identity), nil
}

// DeleteIdentity removes an identity row identified by its (provider, sub)
// primary key and returns the deleted row.
func (m *Manager) DeleteIdentity(ctx context.Context, provider, sub string) (*schema.Identity, error) {
	var identity schema.Identity
	if err := m.PoolConn.Delete(ctx, &identity, schema.IdentityKey{Provider: provider, Sub: sub}); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(identity), nil
}
