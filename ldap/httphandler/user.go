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
// TYPES

// nameParams is the path parameter of a user or group
type nameParams struct {
	Name string `json:"name" help:"Name, which is a user's uid, or cn, and a group's cn"`
}

// userCreateQuery is the query of creating a user
type userCreateQuery struct {
	AllocateGID bool `json:"allocate_gid,omitempty" help:"Set the gidNumber to the uidNumber, for a posixAccount"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerUser registers listing users, and getting, creating, updating
// and deleting one
func registerUser(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("ldap/user", nil, func(path httprequest.PathItem) {
			path.Tag(tagUser)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				var req schema.UserListRequest
				if err := httprequest.Query(r.URL.Query(), &req); err != nil {
					badRequest(w, err)
					return
				}
				list, err := mgr.ListUsers(r.Context(), req)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), list)
			}, func(op httprequest.PathOperation) {
				op.Summary("List users")
				op.Description(doc.Section(3, "GET /ldap/user").Body)
				op.Query(jsonschema.MustFor[schema.UserListRequest]())
				op.JSONResponse(http.StatusOK, listSchema, "Users")
				op.ErrorResponse(http.StatusBadRequest, "Invalid filter or pagination parameters")
				op.ErrorResponse(http.StatusNotFound, "Group not found")
				security(op, auth, schema.ScopeLDAPRead)
			})
		}),
		router.Register("ldap/user/{name}", jsonschema.MustFor[nameParams](), func(path httprequest.PathItem) {
			path.Tag(tagUser)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				user, err := mgr.GetUser(r.Context(), r.PathValue("name"))
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), user)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get a user")
				op.Description(doc.Section(3, "GET /ldap/user/{name}").Body)
				op.JSONResponse(http.StatusOK, objectSchema, "The user")
				op.ErrorResponse(http.StatusNotFound, "User not found")
				security(op, auth, schema.ScopeLDAPRead)
			})
			path.Put(func(w http.ResponseWriter, r *http.Request) {
				var query userCreateQuery
				if err := httprequest.Query(r.URL.Query(), &query); err != nil {
					badRequest(w, err)
					return
				}
				req, err := readAttrs(r)
				if err != nil {
					badRequest(w, err)
					return
				}
				user, err := mgr.CreateUser(r.Context(), r.PathValue("name"), req.Attrs, query.AllocateGID)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), user)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create a user")
				op.Description(doc.Section(3, "PUT /ldap/user/{name}").Body)
				op.Query(jsonschema.MustFor[userCreateQuery]())
				op.RequestBody(putSchema)
				op.JSONResponse(http.StatusCreated, objectSchema, "The user")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or attributes")
				op.ErrorResponse(http.StatusConflict, "The user exists")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Patch(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectPutRequest
				if err := httprequest.Read(r, &req); err != nil {
					badRequest(w, err)
					return
				}
				user, err := mgr.UpdateUser(r.Context(), r.PathValue("name"), req.Attrs)
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), user)
			}, func(op httprequest.PathOperation) {
				op.Summary("Update a user")
				op.Description(doc.Section(3, "PATCH /ldap/user/{name}").Body)
				op.RequestBody(putSchema)
				op.JSONResponse(http.StatusOK, objectSchema, "The user")
				op.ErrorResponse(http.StatusBadRequest, "Invalid attributes")
				op.ErrorResponse(http.StatusNotFound, "User not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Delete(func(w http.ResponseWriter, r *http.Request) {
				user, err := mgr.DeleteUser(r.Context(), r.PathValue("name"))
				if err != nil {
					fail(w, err)
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), user)
			}, func(op httprequest.PathOperation) {
				op.Summary("Delete a user")
				op.Description(doc.Section(3, "DELETE /ldap/user/{name}").Body)
				op.JSONResponse(http.StatusOK, objectSchema, "The user, as it was")
				op.ErrorResponse(http.StatusNotFound, "User not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
		}),
	)
}

// readAttrs reads the request's attributes, which can be empty
func readAttrs(r *http.Request) (schema.ObjectPutRequest, error) {
	var req schema.ObjectPutRequest
	if r.ContentLength == 0 {
		return req, nil
	}
	return req, httprequest.Read(r, &req)
}
