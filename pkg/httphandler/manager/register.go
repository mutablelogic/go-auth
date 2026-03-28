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

package manager

import (
	"errors"
	"net/http"

	// Packages
	managerpkg "github.com/djthorpe/go-auth/pkg/authmanager"
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
	authenticated := middleware.AuthN(manager)
	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}
	registerProtected := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		if authEnabled {
			handler = authenticated(handler)
		}
		register(path, handler, spec)
	}

	register(ConfigHandler(manager))
	registerProtected(UserHandler(manager))
	registerProtected(UserItemHandler(manager))
	registerProtected(UserGroupHandler(manager))
	registerProtected(GroupHandler(manager))
	registerProtected(GroupItemHandler(manager))
	registerProtected(ChangesHandler(manager))
	registerProtected(ScopeHandler(manager))

	return result
}
