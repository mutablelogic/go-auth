package httphandler

import (
	"errors"
	"net/http"

	// Packages
	auth "github.com/mutablelogic/go-auth/auth/httphandler/auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	middleware "github.com/mutablelogic/go-auth/auth/middleware"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

type HTTPRouter interface {
	RegisterPath(path string, params *jsonschema.Schema, pathitem httprequest.PathItem) error
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterAuthHandlers registers auth handlers with the provided router.
func RegisterAuthHandlers(router HTTPRouter, manager *manager.Manager) error {
	authenticated := middleware.AuthN(manager)
	return errors.Join(
		router.RegisterPath(UserInfoHandler(manager, authenticated)),
	)
}

// RegisterManagerHandlers registers auth handlers with the provided router.
func RegisterManagerHandlers(router HTTPRouter, manager *manager.Manager, auth bool) error {
	authenticated := func(fn http.HandlerFunc) http.HandlerFunc { return fn }
	if auth {
		authenticated = middleware.AuthN(manager)
	}
	return errors.Join(
		router.RegisterPath(UserInfoHandler(manager, authenticated)),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func UserInfoHandler(manager *manager.Manager, middleware func(http.HandlerFunc) http.HandlerFunc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return oidc.UserInfoPath, nil, httprequest.NewPathItem(
		"Authenticated User Information",
		"Returns the client-facing identity claims for the authenticated local token.",
		"Auth",
	).Get(
		middleware(func(w http.ResponseWriter, r *http.Request) {
			_ = auth.GetUserInfoHandler(w, r)
		}),
		"Get authenticated user info",
	)
}
