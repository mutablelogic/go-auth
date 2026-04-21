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

package middleware

import (
	"context"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type contextKey string

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	contextKeyUser    contextKey = "auth.user"
	contextKeyKey     contextKey = "auth.key"
	contextKeySession contextKey = "auth.session"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// UserFromContext returns the authenticated user stored by the auth middleware.
func UserFromContext(ctx context.Context) *schema.UserInfo {
	if user, ok := ctx.Value(contextKeyUser).(*schema.UserInfo); ok {
		return user
	}
	return nil
}

// SessionFromContext returns the authenticated session stored by the auth middleware.
func SessionFromContext(ctx context.Context) *schema.Session {
	if session, ok := ctx.Value(contextKeySession).(*schema.Session); ok {
		return session
	}
	return nil
}

// KeyFromContext returns the authenticated API key stored by the auth middleware.
func KeyFromContext(ctx context.Context) *schema.Key {
	if key, ok := ctx.Value(contextKeyKey).(*schema.Key); ok {
		return key
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func withAuthContext(ctx context.Context, user *schema.UserInfo, session *schema.Session) context.Context {
	ctx = context.WithValue(ctx, contextKeyUser, user)
	ctx = context.WithValue(ctx, contextKeySession, session)
	return ctx
}

func withAPIKeyContext(ctx context.Context, user *schema.UserInfo, key *schema.Key) context.Context {
	ctx = context.WithValue(ctx, contextKeyUser, user)
	ctx = context.WithValue(ctx, contextKeyKey, key)
	return ctx
}
