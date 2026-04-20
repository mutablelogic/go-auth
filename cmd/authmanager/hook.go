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
