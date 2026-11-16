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

// Package httphandler registers the HTTP handlers of the LDAP manager: the
// directory's schema, users, groups and their members, and objects by DN
package httphandler

import (
	_ "embed"
	"errors"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed README.md
var HandlerDoc []byte

const (
	// The OpenAPI tags of the operations
	tagSchema = "Directory Schema"
	tagUser   = "Users"
	tagGroup  = "Groups"
	tagObject = "Objects"

	securityScheme = "bearerAuth"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterHandlers registers the handlers of the LDAP manager: listing the
// directory's object classes and attribute types, its users and groups,
// and their members, and its objects, by DN, with binding and changing
// passwords. When auth is true, the handlers need the LDAP scopes.
func RegisterHandlers(manager *manager.Manager, auth bool) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		doc := opts.ParseMarkdown(HandlerDoc)
		for _, tag := range []string{tagSchema, tagUser, tagGroup, tagObject} {
			router.Spec().AddTag(tag, doc.Section(2, tag).Body)
		}
		router.Spec().AddTagGroup("Directory Management", tagSchema, tagUser, tagGroup, tagObject)

		return errors.Join(
			registerSchema(router, manager, auth, doc),
			registerUser(router, manager, auth, doc),
			registerGroup(router, manager, auth, doc),
			registerObject(router, manager, auth, doc),
		)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// security requires the bearer token scheme, with the scopes, when auth is
// true
func security(op httprequest.PathOperation, auth bool, scopes ...string) {
	if auth {
		op.Security(securityScheme, scopes...)
	}
}
