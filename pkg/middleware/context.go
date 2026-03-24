package middleware

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
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
