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
	"net/http"

	// Packages
	authpkg "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// UserGroupHandler returns a path and pathitem for the user group membership endpoint.
func UserGroupHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "user/{user}/group", nil, httprequest.NewPathItem(
		"User group membership operations",
		docBody(doc, 2, "User", "Batch add or remove group memberships for a specific user"),
		"User",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			user, err := schema.UserIDFromString(r.PathValue("user"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			if err := addUserGroup(r.Context(), manager, w, r, user); err != nil {
				httpresponse.Error(w, authpkg.HTTPError(err))
			}
		},
		"Add user groups",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/user/{user}/group").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.UserGroupList]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.User]()),
		opts.WithErrorResponse(400, "Invalid user ID, request body, or group identifiers."),
		opts.WithErrorResponse(404, "User or group not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserWrite, schema.ScopeAuthGroupRead),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			user, err := schema.UserIDFromString(r.PathValue("user"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			if err := removeUserGroup(r.Context(), manager, w, r, user); err != nil {
				httpresponse.Error(w, authpkg.HTTPError(err))
			}
		},
		"Remove user groups",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/user/{user}/group").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.UserGroupList]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.User]()),
		opts.WithErrorResponse(400, "Invalid user ID, request body, or group identifiers."),
		opts.WithErrorResponse(404, "User or group not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserWrite, schema.ScopeAuthGroupRead),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func addUserGroup(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	var req schema.UserGroupList
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	response, err := manager.AddUserGroups(ctx, user, []string(req))
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func removeUserGroup(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	var req schema.UserGroupList
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	response, err := manager.RemoveUserGroups(ctx, user, []string(req))
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}
