package httphandler

import (
	"errors"
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
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

	// Convenience function to register a handler and accumulate any errors
	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}

	// Register handlers
	register(UserHandler(manager))
	register(UserItemHandler(manager))
	register(AuthHandler(manager))

	// Return any errors
	return result
}
