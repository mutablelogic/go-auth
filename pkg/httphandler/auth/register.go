package auth

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

// RegisterAuthHandlers registers auth handlers with the provided router.
func RegisterAuthHandlers(manager *managerpkg.Manager, router server.HTTPRouter) error {
	var result error
	authenticated := middleware.NewMiddleware(manager)

	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}
	registerProtectedAlways := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		register(path, authenticated(handler), spec)
	}

	registerProtectedAlways(UserInfoHandler(manager))
	register(AuthHandler(manager))
	register(AuthorizationHandler(manager))
	register(AuthCodeHandler(manager))
	register(AuthConfigHandler(manager))
	register(RefreshHandler(manager))
	register(RevokeHandler(manager))
	register(ConfigHandler(manager))
	register(ProtectedResourceHandler(manager))
	register(JWKSHandler(manager))

	return result
}
