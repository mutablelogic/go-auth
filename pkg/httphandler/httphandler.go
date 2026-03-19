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
func RegisterHandlers(manager *manager.Manager, router server.HTTPRouter) error {
	var result error
	authenticated := middleware.NewMiddleware(manager)

	// Convenience function to register a handler and accumulate any errors
	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}
	registerProtected := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, authenticated(handler), true, spec))
	}

	// Register handlers
	registerProtected(UserHandler(manager))
	registerProtected(UserItemHandler(manager))
	registerProtected(UserInfoHandler(manager))
	register(AuthHandler(manager))
	register(RefreshHandler(manager))
	register(RevokeHandler(manager))
	register(ConfigHandler(manager))
	register(JWKSHandler(manager))

	// Return any errors
	return result
}
