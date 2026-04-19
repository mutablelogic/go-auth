package main

import (
	"context"
	"fmt"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	server "github.com/mutablelogic/go-server"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type NewUserHook struct {
	server.Cmd
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

func (h NewUserHook) OnUserCreate(_ context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
	h.Logger().InfoContext(h.Context(), "Creating new user", "identity", identity, "meta", meta)

	if meta.Status == nil {
		meta.Status = types.Ptr(schema.UserStatusActive)
	}

	return meta, nil
}

func (h NewUserHook) OnIdentityLink(_ context.Context, identity schema.IdentityInsert, existing *schema.User) error {
	h.Logger().InfoContext(h.Context(), "Linking identity to existing user", "identity", identity, "user", existing)

	// Check email addresses match exactly
	if identity.Email != existing.Email {
		return fmt.Errorf("identity email does not match existing user email")
	}

	// Allow the link to proceed without error, but do not modify the existing user
	return nil
}
