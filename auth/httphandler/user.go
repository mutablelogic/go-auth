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

// UserHandler returns a path and pathitem for the user collection endpoint.
func UserHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "user", nil, httprequest.NewPathItem(
		"User operations",
		"Operations on users",
		"User",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listUser(r.Context(), manager, w, r)
		},
		"List users",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/user").Body),
		opts.WithQuery(jsonschema.MustFor[schema.UserListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.UserList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserRead),
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = createUser(r.Context(), manager, w, r)
		},
		"Create user",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/user").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.UserMeta]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.User]()),
		opts.WithErrorResponse(400, "Invalid request body or user creation failure."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserRead, schema.ScopeAuthUserWrite),
	)
}

// UserResourceHandler returns a path and pathitem for the user resource endpoint.
func UserResourceHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "user/{user}", nil, httprequest.NewPathItem(
		"User operations",
		"Operations on a specific user",
		"User",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			user, err := schema.UserIDFromString(r.PathValue("user"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = getUser(r.Context(), manager, w, r, user)
		},
		"Get user",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/user/{user}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.User]()),
		opts.WithErrorResponse(400, "Invalid user ID."),
		opts.WithErrorResponse(404, "User not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserRead),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			user, err := schema.UserIDFromString(r.PathValue("user"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = updateUser(r.Context(), manager, w, r, user)
		},
		"Update user",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/user/{user}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.UserMeta]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.User]()),
		opts.WithErrorResponse(400, "Invalid user ID or request body."),
		opts.WithErrorResponse(404, "User not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserRead, schema.ScopeAuthUserWrite),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			user, err := schema.UserIDFromString(r.PathValue("user"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = deleteUser(r.Context(), manager, w, r, user)
		},
		"Delete user",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/user/{user}").Body),
		opts.WithErrorResponse(400, "Invalid user ID."),
		opts.WithErrorResponse(404, "User not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthUserWrite),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createUser(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.UserMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	user, err := manager.CreateUser(ctx, req, nil)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), user)
}

func listUser(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.UserListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	users, err := manager.ListUsers(ctx, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), users)
}

func getUser(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	response, err := manager.GetUser(ctx, user)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func updateUser(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, user schema.UserID) error {
	var req schema.UserMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	response, err := manager.UpdateUser(ctx, user, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func deleteUser(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, _ *http.Request, user schema.UserID) error {
	_, err := manager.DeleteUser(ctx, user)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.Empty(w, http.StatusNoContent)
}
