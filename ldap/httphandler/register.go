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
	"net/http"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
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

// httpErr translates an error from the manager into an HTTP error: the
// manager's own are HTTP errors already
func httpErr(err error) error {
	var httpErr httpresponse.Err
	var authErr auth.Err
	switch {
	case errors.As(err, &httpErr):
		return err
	case errors.As(err, &authErr):
		return auth.HTTPError(err)
	default:
		return httpresponse.ErrInternalError.With(err)
	}
}

// fail writes the error, as an HTTP error
func fail(w http.ResponseWriter, err error) {
	httpresponse.Error(w, httpErr(err))
}

// badRequest writes a bad request, with the error
func badRequest(w http.ResponseWriter, err error) {
	httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
}
