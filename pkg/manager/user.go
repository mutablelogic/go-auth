package manager

import (
	"context"
	"strings"

	// Packages
	auth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
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
	if err := m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
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
		return nil, dbErr(err)
	}

	// Re-fetch so that Email/Claims/Groups/Scopes reflect any transactional work.
	return m.GetUser(ctx, user.ID)
}

func (m *Manager) GetUser(ctx context.Context, user schema.UserID) (*schema.User, error) {
	var result schema.User
	if err := m.PoolConn.Get(ctx, &result, user); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) UpdateUser(ctx context.Context, user schema.UserID, meta schema.UserMeta) (*schema.User, error) {
	if err := m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		rowMeta := meta
		rowMeta.Groups = nil

		hasRowPatch := strings.TrimSpace(rowMeta.Name) != "" || strings.TrimSpace(rowMeta.Email) != "" || rowMeta.Status != nil || rowMeta.Meta != nil || rowMeta.ExpiresAt != nil
		hasGroups := meta.Groups != nil
		if !hasRowPatch && !hasGroups {
			return auth.ErrBadParameter.With("no fields to update")
		}

		if hasRowPatch {
			var updated schema.User
			if err := conn.Update(ctx, &updated, user, rowMeta); err != nil {
				return err
			}
		} else {
			var existing schema.User
			if err := conn.Get(ctx, &existing, user); err != nil {
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
		return nil, dbErr(err)
	}
	return m.GetUser(ctx, user)
}

func (m *Manager) DeleteUser(ctx context.Context, user schema.UserID) (*schema.User, error) {
	var result schema.User
	if err := m.PoolConn.Delete(ctx, &result, user); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

func (m *Manager) ListUsers(ctx context.Context, req schema.UserListRequest) (*schema.UserList, error) {
	result := schema.UserList{OffsetLimit: req.OffsetLimit}
	if err := m.PoolConn.List(ctx, &result, req); err != nil {
		return nil, dbErr(err)
	}
	return types.Ptr(result), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func replaceUserGroups(ctx context.Context, conn pg.Conn, user schema.UserID, groups []string) error {
	normalized, err := normalizeUserGroups(groups)
	if err != nil {
		return err
	}

	if err := conn.With("user", user).Exec(ctx, `
DELETE FROM ${"schema"}.user_group
WHERE "user" = @user
`); err != nil {
		return err
	}

	if len(normalized) == 0 {
		return nil
	}

	return conn.With("user", user).With("groups", normalized).Exec(ctx, `
INSERT INTO ${"schema"}.user_group ("user", "group")
SELECT @user, group_id
FROM unnest(@groups::text[]) AS group_id
`)
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
