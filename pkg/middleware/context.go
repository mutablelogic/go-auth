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
	schema "github.com/djthorpe/go-auth/schema/auth"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type contextKey string

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	contextKeyClaims  contextKey = "auth.claims"
	contextKeyUser    contextKey = "auth.user"
	contextKeySession contextKey = "auth.session"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ClaimsFromContext returns JWT claims stored by the auth middleware.
func ClaimsFromContext(ctx context.Context) (map[string]any, bool) {
	claims, ok := ctx.Value(contextKeyClaims).(map[string]any)
	return claims, ok
}

// UserFromContext returns the authenticated user stored by the auth middleware.
func UserFromContext(ctx context.Context) (*schema.User, bool) {
	user, ok := ctx.Value(contextKeyUser).(*schema.User)
	return user, ok
}

// SessionFromContext returns the authenticated session stored by the auth middleware.
func SessionFromContext(ctx context.Context) (*schema.Session, bool) {
	session, ok := ctx.Value(contextKeySession).(*schema.Session)
	return session, ok
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func withAuthContext(ctx context.Context, claims map[string]any, user *schema.User, session *schema.Session) context.Context {
	ctx = context.WithValue(ctx, contextKeyClaims, claims)
	ctx = context.WithValue(ctx, contextKeyUser, user)
	ctx = context.WithValue(ctx, contextKeySession, session)
	return ctx
}
