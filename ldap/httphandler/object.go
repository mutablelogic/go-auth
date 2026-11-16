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
	"io"
	"net/http"

	// Packages
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// dnParams is the path parameter of an object
type dnParams struct {
	DN string `json:"dn" help:"Distinguished name, relative to the base DN, or under it, escaped as a path segment"`
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// The most a bind's password can be
const maxPassword = 1024

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerObject registers listing objects, getting, creating, updating and
// deleting one, binding as one, and changing its password
func registerObject(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("ldap/object", nil, func(path httprequest.PathItem) {
			path.Tag(tagObject)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectListRequest
				if err := httprequest.Query(r.URL.Query(), &req); err != nil {
					badRequest(w, err)
					return
				}
				list, err := mgr.List(r.Context(), req)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), list)
			}, func(op httprequest.PathOperation) {
				op.Summary("List objects")
				op.Description(doc.Section(3, "GET /ldap/object").Body)
				op.Query(jsonschema.MustFor[schema.ObjectListRequest]())
				op.JSONResponse(http.StatusOK, listSchema, "Objects")
				op.ErrorResponse(http.StatusBadRequest, "Invalid filter, prefix or pagination parameters")
				op.ErrorResponse(http.StatusNotFound, "Prefix not found")
				security(op, auth, schema.ScopeLDAPRead)
			})
		}),
		router.Register("ldap/object/{dn}", jsonschema.MustFor[dnParams](), func(path httprequest.PathItem) {
			path.Tag(tagObject)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				object, err := mgr.Get(r.Context(), r.PathValue("dn"))
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get an object")
				op.Description(doc.Section(3, "GET /ldap/object/{dn}").Body)
				op.JSONResponse(http.StatusOK, objectSchema, "The object")
				op.ErrorResponse(http.StatusBadRequest, "Invalid DN")
				op.ErrorResponse(http.StatusNotFound, "Object not found")
				security(op, auth, schema.ScopeLDAPRead)
			})
			path.Put(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectPutRequest
				if err := httprequest.Read(r, &req); err != nil {
					badRequest(w, err)
					return
				}
				object, err := mgr.Create(r.Context(), r.PathValue("dn"), req.Attrs)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), object)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create an object")
				op.Description(doc.Section(3, "PUT /ldap/object/{dn}").Body)
				op.RequestBody(putSchema)
				op.JSONResponse(http.StatusCreated, objectSchema, "The object")
				op.ErrorResponse(http.StatusBadRequest, "Invalid DN or attributes")
				op.ErrorResponse(http.StatusNotFound, "Parent not found")
				op.ErrorResponse(http.StatusConflict, "The object exists")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Patch(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectPutRequest
				if err := httprequest.Read(r, &req); err != nil {
					badRequest(w, err)
					return
				}
				object, err := mgr.Update(r.Context(), r.PathValue("dn"), req.Attrs)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
			}, func(op httprequest.PathOperation) {
				op.Summary("Update an object")
				op.Description(doc.Section(3, "PATCH /ldap/object/{dn}").Body)
				op.RequestBody(putSchema)
				op.JSONResponse(http.StatusOK, objectSchema, "The object")
				op.ErrorResponse(http.StatusBadRequest, "Invalid DN or attributes")
				op.ErrorResponse(http.StatusNotFound, "Object not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Delete(func(w http.ResponseWriter, r *http.Request) {
				object, err := mgr.Delete(r.Context(), r.PathValue("dn"))
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
			}, func(op httprequest.PathOperation) {
				op.Summary("Delete an object")
				op.Description(doc.Section(3, "DELETE /ldap/object/{dn}").Body)
				op.JSONResponse(http.StatusOK, objectSchema, "The object, as it was")
				op.ErrorResponse(http.StatusBadRequest, "Invalid DN")
				op.ErrorResponse(http.StatusNotFound, "Object not found")
				op.ErrorResponse(http.StatusConflict, "The object has children")
				security(op, auth, schema.ScopeLDAPWrite)
			})
		}),
		router.Register("ldap/object/{dn}/bind", jsonschema.MustFor[dnParams](), func(path httprequest.PathItem) {
			path.Tag(tagObject)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				password, err := io.ReadAll(io.LimitReader(r.Body, maxPassword+1))
				if err != nil {
					badRequest(w, err)
					return
				} else if len(password) > maxPassword {
					badRequest(w, errors.New("the password is too long"))
					return
				}
				object, err := mgr.Bind(r.Context(), r.PathValue("dn"), string(password))
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
			}, func(op httprequest.PathOperation) {
				op.Summary("Bind as an object")
				op.Description(doc.Section(3, "POST /ldap/object/{dn}/bind").Body)
				op.RequestBody(jsonschema.MustFor[string](), types.ContentTypeTextPlain)
				op.JSONResponse(http.StatusOK, objectSchema, "The object")
				op.ErrorResponse(http.StatusBadRequest, "Invalid DN, or a password which is too long")
				op.ErrorResponse(http.StatusUnauthorized, "Invalid credentials")
				security(op, auth, schema.ScopeLDAPWrite)
			})
		}),
		router.Register("ldap/object/{dn}/password", jsonschema.MustFor[dnParams](), func(path httprequest.PathItem) {
			path.Tag(tagObject)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectPasswordRequest
				if err := httprequest.Read(r, &req); err != nil {
					badRequest(w, err)
					return
				}
				response, err := mgr.ChangePassword(r.Context(), r.PathValue("dn"), req)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
			}, func(op httprequest.PathOperation) {
				op.Summary("Change an object's password")
				op.Description(doc.Section(3, "POST /ldap/object/{dn}/password").Body)
				op.RequestBody(jsonschema.MustFor[schema.ObjectPasswordRequest]())
				op.JSONResponse(http.StatusOK, passwordSchema, "The object, with the password, when it was generated")
				op.ErrorResponse(http.StatusBadRequest, "Invalid DN or request body")
				op.ErrorResponse(http.StatusUnauthorized, "The old password is wrong")
				op.ErrorResponse(http.StatusNotFound, "Object not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
		}),
	)
}
