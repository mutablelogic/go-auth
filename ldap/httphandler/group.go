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
	"context"
	"errors"
	"net/http"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
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

// registerGroup registers listing groups, getting, creating, updating and
// deleting one, and adding and removing its members
func registerGroup(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("ldap/group", nil, func(path httprequest.PathItem) {
			path.Tag(tagGroup)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				var req schema.GroupListRequest
				if err := httprequest.Query(r.URL.Query(), &req); err != nil {
					httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
					return
				}
				list, err := mgr.ListGroups(r.Context(), req)
				if err != nil {
					httpresponse.Error(w, goauth.HTTPError(err))
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), list)
			}, func(op httprequest.PathOperation) {
				op.Summary("List groups")
				op.Description(doc.Section(3, "GET /ldap/group").Body)
				op.Query(jsonschema.MustFor[schema.GroupListRequest]())
				op.JSONResponse(http.StatusOK, listSchema, "Groups")
				op.ErrorResponse(http.StatusBadRequest, "Invalid filter or pagination parameters")
				op.ErrorResponse(http.StatusNotFound, "User not found")
				security(op, auth, schema.ScopeLDAPRead)
			})
		}),
		router.Register("ldap/group/{name}", jsonschema.MustFor[nameParams](), func(path httprequest.PathItem) {
			path.Tag(tagGroup)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				group, err := mgr.GetGroup(r.Context(), r.PathValue("name"))
				if err != nil {
					httpresponse.Error(w, goauth.HTTPError(err))
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get a group")
				op.Description(doc.Section(3, "GET /ldap/group/{name}").Body)
				op.JSONResponse(http.StatusOK, objectSchema, "The group")
				op.ErrorResponse(http.StatusNotFound, "Group not found")
				security(op, auth, schema.ScopeLDAPRead)
			})
			path.Put(func(w http.ResponseWriter, r *http.Request) {
				req, err := readAttrs(r)
				if err != nil {
					httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
					return
				}
				group, err := mgr.CreateGroup(r.Context(), r.PathValue("name"), req.Attrs)
				if err != nil {
					httpresponse.Error(w, goauth.HTTPError(err))
					return
				}
				httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), group)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create a group")
				op.Description(doc.Section(3, "PUT /ldap/group/{name}").Body)
				op.RequestBody(putSchema)
				op.JSONResponse(http.StatusCreated, objectSchema, "The group")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or attributes")
				op.ErrorResponse(http.StatusConflict, "The group exists")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Patch(func(w http.ResponseWriter, r *http.Request) {
				var req schema.ObjectPutRequest
				if err := httprequest.Read(r, &req); err != nil {
					httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
					return
				}
				group, err := mgr.UpdateGroup(r.Context(), r.PathValue("name"), req.Attrs)
				if err != nil {
					httpresponse.Error(w, goauth.HTTPError(err))
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
			}, func(op httprequest.PathOperation) {
				op.Summary("Update a group")
				op.Description(doc.Section(3, "PATCH /ldap/group/{name}").Body)
				op.RequestBody(putSchema)
				op.JSONResponse(http.StatusOK, objectSchema, "The group")
				op.ErrorResponse(http.StatusBadRequest, "Invalid attributes")
				op.ErrorResponse(http.StatusNotFound, "Group not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Delete(func(w http.ResponseWriter, r *http.Request) {
				group, err := mgr.DeleteGroup(r.Context(), r.PathValue("name"))
				if err != nil {
					httpresponse.Error(w, goauth.HTTPError(err))
					return
				}
				httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
			}, func(op httprequest.PathOperation) {
				op.Summary("Delete a group")
				op.Description(doc.Section(3, "DELETE /ldap/group/{name}").Body)
				op.JSONResponse(http.StatusOK, objectSchema, "The group, as it was")
				op.ErrorResponse(http.StatusNotFound, "Group not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
		}),
		router.Register("ldap/group/{name}/user", jsonschema.MustFor[nameParams](), func(path httprequest.PathItem) {
			path.Tag(tagGroup)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				changeMembers(w, r, mgr.AddGroupUsers)
			}, func(op httprequest.PathOperation) {
				op.Summary("Add users to a group")
				op.Description(doc.Section(3, "POST /ldap/group/{name}/user").Body)
				op.RequestBody(jsonschema.MustFor[[]string]())
				op.JSONResponse(http.StatusOK, objectSchema, "The group")
				op.ErrorResponse(http.StatusBadRequest, "No users")
				op.ErrorResponse(http.StatusNotFound, "Group or user not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
			path.Delete(func(w http.ResponseWriter, r *http.Request) {
				changeMembers(w, r, mgr.RemoveGroupUsers)
			}, func(op httprequest.PathOperation) {
				op.Summary("Remove users from a group")
				op.Description(doc.Section(3, "DELETE /ldap/group/{name}/user").Body)
				op.RequestBody(jsonschema.MustFor[[]string]())
				op.JSONResponse(http.StatusOK, objectSchema, "The group")
				op.ErrorResponse(http.StatusBadRequest, "No users")
				op.ErrorResponse(http.StatusNotFound, "Group or user not found")
				security(op, auth, schema.ScopeLDAPWrite)
			})
		}),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

// changeMembers reads the users' names, and adds them to the group, or
// removes them
func changeMembers(w http.ResponseWriter, r *http.Request, fn func(context.Context, string, ...string) (*schema.Object, error)) {
	var users []string
	if err := httprequest.Read(r, &users); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	group, err := fn(r.Context(), r.PathValue("name"), users...)
	if err != nil {
		httpresponse.Error(w, goauth.HTTPError(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}
