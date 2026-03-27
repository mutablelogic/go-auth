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

	authenticated := middleware.AuthN(manager)
	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}
	registerProtectedAlways := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		register(path, authenticated(handler), spec)
	}

	registerProtectedAlways(UserInfoHandler(manager))
	register(AuthorizationHandler(manager))
	register(AuthCodeHandler(manager))
	register(RevokeHandler(manager))
	register(ConfigHandler(manager))
	register(ProtectedResourceHandler(manager))
	register(JWKSHandler(manager))
	for _, route := range manager.HTTPHandlers() {
		register(route.Path, route.Handler, route.Spec)
	}

	return result
}
