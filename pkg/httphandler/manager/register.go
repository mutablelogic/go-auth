package manager

import (
	"errors"
	"net/http"

	// Packages
	managerpkg "github.com/djthorpe/go-auth/pkg/manager"
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

// RegisterManagerHandlers registers manager resource handlers with the provided router.
func RegisterManagerHandlers(manager *managerpkg.Manager, router server.HTTPRouter, authEnabled bool) error {
	var result error
	authenticated := middleware.NewMiddleware(manager)

	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}
	registerProtected := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		if authEnabled {
			handler = authenticated(handler)
		}
		register(path, handler, spec)
	}

	registerProtected(GroupHandler(manager))
	registerProtected(GroupItemHandler(manager))
	registerProtected(ChangesHandler(manager))
	registerProtected(ScopeHandler(manager))
	registerProtected(UserHandler(manager))
	registerProtected(UserItemHandler(manager))
	registerProtected(UserGroupHandler(manager))

	return result
}
