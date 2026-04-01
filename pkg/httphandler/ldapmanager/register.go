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

	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	markdown "github.com/djthorpe/go-auth/pkg/markdown"
	middleware "github.com/djthorpe/go-auth/pkg/middleware"
	schema "github.com/djthorpe/go-auth/schema/auth"
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

// RegisterHandlers registers LDAP manager resource handlers with the provided router.
func RegisterHandlers(manager *ldap.Manager, auth middleware.TokenVerifier, router server.HTTPRouter) error {
	r := router.(Register)
	doc := markdown.Parse(doc)

	// Add description
	router.Spec().Info.Description = doc.Section(1, "LDAP Manager").Body

	// Add tag groups
	router.Spec().AddTagGroup("LDAP Management", "Object Schema", "Users", "Groups", "Object")
	router.Spec().AddTag("Object Schema", doc.Section(2, "Object Schema").Body)
	router.Spec().AddTag("Users", doc.Section(2, "Users").Body)
	router.Spec().AddTag("Groups", doc.Section(2, "Groups").Body)
	router.Spec().AddTag("Object", doc.Section(2, "Object").Body)

	// Register the security scheme
	if auth != nil {
		if err := r.RegisterSecurityScheme(schema.SecurityBearerAuth, middleware.NewBearerAuth(auth)); err != nil {
			return err
		}
	}

	// Register the handlers, and return any errors
	return errors.Join(
		r.RegisterPath(ClassHandler(manager, doc)),
		r.RegisterPath(AttrHandler(manager, doc)),
		r.RegisterPath(UserHandler(manager, doc)),
		r.RegisterPath(UserResourceHandler(manager, doc)),
		r.RegisterPath(GroupHandler(manager, doc)),
		r.RegisterPath(GroupResourceHandler(manager, doc)),
		r.RegisterPath(GroupUserResourceHandler(manager, doc)),
		r.RegisterPath(ObjectHandler(manager, doc)),
		r.RegisterPath(ObjectResourceHandler(manager, doc)),
		r.RegisterPath(ObjectBindHandler(manager, doc)),
		r.RegisterPath(ObjectPasswordHandler(manager, doc)),
	)
}
