package middleware

import (
	"fmt"
	"net/http"

	// Packages
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type bearerAuth struct {
	verifier TokenVerifier
}

var _ httprouter.SecurityScheme = (*bearerAuth)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewBearerAuth(verifier TokenVerifier) *bearerAuth {
	return &bearerAuth{
		verifier: verifier,
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (b *bearerAuth) Spec() openapi.SecurityScheme {
	return openapi.SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
	}
}

func (b *bearerAuth) Wrap(handler http.HandlerFunc, scopes []string) http.HandlerFunc {
	wrapper := NewMiddleware(b.verifier)
	return wrapper(func(w http.ResponseWriter, r *http.Request) {
		if user := UserFromContext(r.Context()); user == nil {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized).With("invalid token: no user in context"))
			return
		} else if !user.HasAllScopes(scopes...) {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusForbidden).With("insufficient permissions"), fmt.Sprintf("Required scopes: %q", scopes))
			return
		}
		handler(w, r)
	})
}
