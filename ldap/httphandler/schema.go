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

package httphandler

import (
	"errors"
	"net/http"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerSchema registers listing the directory's object classes and
// attribute types
func registerSchema(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("ldap/class", nil, func(path httprequest.PathItem) {
			path.Tag(tagSchema)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectClassListRequest
				if err := httprequest.Query(r.URL.Query(), &req); err != nil {
					badRequest(w, err)
					return
				}
				classes, err := mgr.ListObjectClasses(r.Context(), req)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), classes)
			}, func(op httprequest.PathOperation) {
				op.Summary("List object classes")
				op.Description(doc.Section(3, "GET /ldap/class").Body)
				op.Query(jsonschema.MustFor[schema.ObjectClassListRequest]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[schema.ObjectClassListResponse](), "Object classes, by name")
				op.ErrorResponse(http.StatusBadRequest, "Invalid filter or pagination parameters")
				security(op, auth, schema.ScopeLDAPRead)
			})
		}),
		router.Register("ldap/attr", nil, func(path httprequest.PathItem) {
			path.Tag(tagSchema)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				var req schema.AttributeTypeListRequest
				if err := httprequest.Query(r.URL.Query(), &req); err != nil {
					badRequest(w, err)
					return
				}
				attrs, err := mgr.ListAttributeTypes(r.Context(), req)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), attrs)
			}, func(op httprequest.PathOperation) {
				op.Summary("List attribute types")
				op.Description(doc.Section(3, "GET /ldap/attr").Body)
				op.Query(jsonschema.MustFor[schema.AttributeTypeListRequest]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[schema.AttributeTypeListResponse](), "Attribute types, by name")
				op.ErrorResponse(http.StatusBadRequest, "Invalid filter or pagination parameters")
				security(op, auth, schema.ScopeLDAPRead)
			})
		}),
	)
}
