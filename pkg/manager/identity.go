package manager

import (
	"context"
	"errors"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	pg "github.com/mutablelogic/go-pg"
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

func (m *Manager) ListIdentities(ctx context.Context, req schema.IdentityListRequest) (*schema.IdentityList, error) {
	result := schema.IdentityList{OffsetLimit: req.OffsetLimit}
	if err := m.PoolConn.List(ctx, &result, req); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) LoginWithIdentity(ctx context.Context, meta schema.IdentityInsert, createMeta ...map[string]any) (*schema.User, *schema.Session, error) {
	if meta.Provider == "" {
		return nil, nil, auth.ErrBadParameter.With("issuer is required")
	}
	if meta.Sub == "" {
		return nil, nil, auth.ErrBadParameter.With("sub is required")
	}

	var userCreateMeta map[string]any
	if len(createMeta) > 0 {
		userCreateMeta = createMeta[0]
	}

	var user schema.UserID
	var session schema.Session
	if err := m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		// Find an existing identity row with the same (provider, sub) key.
		var identity schema.Identity
		createdUser := false
		if err := conn.Get(ctx, &identity, schema.IdentityKey{Provider: meta.Provider, Sub: meta.Sub}); err != nil {
			if !errors.Is(dbErr(err), auth.ErrNotFound) {
				return err
			}

			if meta.Email == "" {
				return auth.ErrBadParameter.With("email is required")
			}

			// Reject linking to an existing user with the same canonical email.
			// This is to prevent hijacking an existing account by creating a new identity with the same email.
			// We should only allow linking for logged-in users, and we'll do that path later.
			var users schema.UserList
			if err := conn.List(ctx, &users, schema.UserListRequest{Email: meta.Email}); err != nil {
				return err
			}
			if users.Count > 0 {
				return auth.ErrConflict.Withf("user already exists for email %q", meta.Email)
			}

			// No matching user exists, so create a new user and identity
			usermeta := schema.UserMeta{
				Name:  meta.Name(),
				Email: meta.Email,
				Meta:  userCreateMeta,
			}
			if m.userhook != nil {
				var err error
				if usermeta, err = m.userhook(ctx, meta, usermeta); err != nil {
					return err
				}
			}

			var created schema.User
			if err := conn.Insert(ctx, &created, usermeta); err != nil {
				return err
			}
			if err := conn.With("user", created.ID).Insert(ctx, nil, types.Value(&meta)); err != nil {
				return err
			}
			user = created.ID
			createdUser = true
		} else {
			user = identity.User
		}

		// Successful login, update identity with new email/claims and modified_at timestamp.
		if !createdUser {
			if err := conn.Update(ctx, &identity, identity.IdentityKey, meta.IdentityMeta); err != nil {
				return err
			}
		}

		// Create a new session for the user.
		if err := conn.Insert(ctx, &session, schema.SessionInsert{
			User:      user,
			ExpiresIn: types.Ptr(m.sessionttl),
		}); err != nil {
			return err
		} else {
			session.User = user
		}

		// Return success
		return nil
	}); err != nil {
		return nil, nil, dbErr(err)
	}

	// Return the user associated with the identity, which may have been updated by the transaction.
	user_, err := m.GetUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	return user_, types.Ptr(session), nil
}
