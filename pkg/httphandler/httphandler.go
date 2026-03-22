package httphandler

import (
	"errors"
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	server "github.com/mutablelogic/go-server"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Register interface {
	RegisterFunc(path string, handler http.HandlerFunc, middleware bool, spec *openapi.PathItem) error
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterHandlers registers all handlers for this package with the provided router and manager.
func RegisterHandlers(manager *manager.Manager, router server.HTTPRouter, auth bool) error {
	var result error
	authenticated := middleware.NewMiddleware(manager)

	// Convenience functions to register handlers and accumulate any errors
	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}
	registerProtected := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		if auth {
			handler = authenticated(handler)
		}
		register(path, handler, spec)
	}
	registerProtectedAlways := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		register(path, authenticated(handler), spec)
	}

	// Register protected handlers
	registerProtected(GroupHandler(manager))
	registerProtected(GroupItemHandler(manager))
	registerProtected(ScopeHandler(manager))
	registerProtected(UserHandler(manager))
	registerProtected(UserItemHandler(manager))
	registerProtected(UserGroupHandler(manager))

	// Register auth handlers
	registerProtectedAlways(UserInfoHandler(manager))
	register(AuthHandler(manager))
	register(AuthCredentialsHandler(manager))
	register(AuthCodeHandler(manager))
	register(AuthConfigHandler(manager))
	register(RefreshHandler(manager))
	register(RevokeHandler(manager))
	register(ConfigHandler(manager))
	register(JWKSHandler(manager))

	// Return any errors
	return result
}
