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
	_ "embed"
	"errors"

	// Packages
	managerpkg "github.com/mutablelogic/go-auth/pkg/authmanager"
	markdown "github.com/mutablelogic/go-auth/pkg/markdown"
	middleware "github.com/mutablelogic/go-auth/pkg/middleware"
	schema "github.com/mutablelogic/go-auth/schema/auth"
	server "github.com/mutablelogic/go-server"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Register interface {
	RegisterPath(path string, params *jsonschema.Schema, pathitem httprequest.PathItem) error
	RegisterSecurityScheme(name string, scheme httprouter.SecurityScheme) error
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed README.md
var doc string

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterManagerHandlers registers manager resource handlers with the provided router.
func RegisterManagerHandlers(manager *managerpkg.Manager, router server.HTTPRouter, auth bool) error {
	r := router.(Register)
	doc := markdown.Parse(doc)

	// Add description
	router.Spec().Info.Description = doc.Section(1, "Auth Manager").Body

	// Add tag groups
	router.Spec().AddTagGroup("Auth Management", "Configuration", "User", "Group", "Scope", "Changes")
	router.Spec().AddTag("Configuration", doc.Section(2, "Configuration").Body)
	router.Spec().AddTag("User", doc.Section(2, "User").Body)
	router.Spec().AddTag("Group", doc.Section(2, "Group").Body)
	router.Spec().AddTag("Scope", doc.Section(2, "Scope").Body)
	router.Spec().AddTag("Changes", doc.Section(2, "Changes").Body)

	// Register the security scheme
	if auth {
		if err := r.RegisterSecurityScheme(schema.SecurityBearerAuth, middleware.NewBearerAuth(manager)); err != nil {
			return err
		}
	}

	// Register the security schemes, then the paths
	return errors.Join(
		r.RegisterPath(ConfigHandler(manager, doc)),
		r.RegisterPath(UserHandler(manager, doc)),
		r.RegisterPath(UserResourceHandler(manager, doc)),
		r.RegisterPath(UserGroupHandler(manager, doc)),
		r.RegisterPath(GroupHandler(manager, doc)),
		r.RegisterPath(GroupItemHandler(manager, doc)),
		r.RegisterPath(ChangesHandler(manager, doc)),
		r.RegisterPath(ScopeHandler(manager, doc)),
	)
}
