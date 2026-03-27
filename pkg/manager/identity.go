package manager

import (
	"context"
	"errors"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	uuid "github.com/google/uuid"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CreateIdentity inserts a new identity row for an existing user.
func (m *Manager) CreateIdentity(ctx context.Context, user uuid.UUID, identity schema.IdentityInsert) (_ *schema.Identity, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.CreateIdentity",
		attribute.String("user", schema.UserID(user).String()),
		attribute.String("identity", identity.String()),
	)
	defer func() { endSpan(err) }()

	var result schema.Identity
	if err = m.PoolConn.With(
		"user", schema.UserID(user),
	).Insert(ctx, &result, types.Value(&identity)); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

// GetIdentity retrieves a single identity by its (provider, sub) primary key.
func (m *Manager) GetIdentity(ctx context.Context, key schema.IdentityKey) (_ *schema.Identity, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.GetIdentity", attribute.String("key", key.String()))
	defer func() { endSpan(err) }()

	var identity schema.Identity
	if err = m.PoolConn.Get(ctx, &identity, key); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(identity), nil
}

// UpdateIdentity refreshes the mutable fields (email, claims) on an existing
// identity row identified by (provider, sub). modified_at is always updated.
func (m *Manager) UpdateIdentity(ctx context.Context, key schema.IdentityKey, meta schema.IdentityMeta) (_ *schema.Identity, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.UpdateIdentity",
		attribute.String("key", key.String()),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	var identity schema.Identity
	if err = m.PoolConn.Update(ctx, &identity, key, meta); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(identity), nil
}

// DeleteIdentity removes an identity row identified by its (provider, sub)
// primary key and returns the deleted row.
func (m *Manager) DeleteIdentity(ctx context.Context, key schema.IdentityKey) (_ *schema.Identity, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.DeleteIdentity", attribute.String("key", key.String()))
	defer func() { endSpan(err) }()

	var identity schema.Identity
	if err = m.PoolConn.Delete(ctx, &identity, key); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(identity), nil
}

func (m *Manager) ListIdentities(ctx context.Context, req schema.IdentityListRequest) (_ *schema.IdentityList, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.ListIdentities", attribute.String("request", req.String()))
	defer func() { endSpan(err) }()

	result := schema.IdentityList{OffsetLimit: req.OffsetLimit}
	if err = m.PoolConn.List(ctx, &result, req); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) LoginWithIdentity(ctx context.Context, meta schema.IdentityInsert, createMeta map[string]any) (_ *schema.User, _ *schema.Session, err error) {
	attrs := []attribute.KeyValue{attribute.String("meta", meta.String())}
	if createMeta != nil {
		attrs = append(attrs, attribute.String("create_meta", types.Stringify(createMeta)))
	}
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "manager.LoginWithIdentity", attrs...)
	defer func() { endSpan(err) }()

	if meta.Provider == "" {
		err = auth.ErrBadParameter.With("issuer is required")
		return nil, nil, err
	}
	if meta.Sub == "" {
		err = auth.ErrBadParameter.With("sub is required")
		return nil, nil, err
	}

	var user schema.UserID
	var session schema.Session
	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		// Find an existing identity row with the same (provider, sub) key.
		var identity schema.Identity
		updateIdentity := false
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
				existing := users.Body[0]
				if hook, ok := m.hooks.(IdentityLinkHook); ok {
					if err := hook.OnIdentityLink(ctx, meta, &existing); err != nil {
						return err
					}
					if err := conn.With("user", existing.ID).Insert(ctx, nil, types.Value(&meta)); err != nil {
						return err
					}
					user = existing.ID
				} else {
					return auth.ErrConflict.Withf("user already exists for email %q", meta.Email)
				}
			} else {
				// No matching user exists, so create a new user and identity
				usermeta := schema.UserMeta{
					Name:  meta.Name(),
					Email: meta.Email,
					Meta:  createMeta,
				}

				if hook, ok := m.hooks.(UserCreationHook); ok {
					var err error
					if usermeta, err = hook.OnUserCreate(ctx, meta, usermeta); err != nil {
						return err
					}
				}

				// Create a new user and set groups
				var created schema.User
				rowMeta := usermeta
				rowMeta.Groups = nil
				if err := conn.Insert(ctx, &created, rowMeta); err != nil {
					return err
				}
				if err := replaceUserGroups(ctx, conn, created.ID, usermeta.Groups); err != nil {
					return err
				}
				if err := conn.With("user", created.ID).Insert(ctx, nil, types.Value(&meta)); err != nil {
					return err
				}
				user = created.ID
			}
		} else {
			user = identity.User
			updateIdentity = true
		}

		// Successful login, update identity with new email/claims and modified_at timestamp.
		if updateIdentity {
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
		err = dbErr(err)
		return nil, nil, err
	}

	// Return the user associated with the identity, which may have been updated by the transaction.
	user_, err := m.GetUser(ctx, user)
	if err != nil {
		return nil, nil, err
	}
	return user_, types.Ptr(session), nil
}
