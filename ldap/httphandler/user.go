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
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	// Packages
	ldap "github.com/mutablelogic/go-auth/ldap/manager"
	markdown "github.com/mutablelogic/go-auth/pkg/markdown"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func UserHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "user", nil, httprequest.NewPathItem(
		"User operations",
		"Operations on LDAP users",
		"Users",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listUsers(r.Context(), manager, w, r)
		},
		"List users",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/user").Body),
		opts.WithQuery(jsonschema.MustFor[schema.ObjectListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.ObjectList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
	)
}

func UserResourceHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "user/{cn}", nil, httprequest.NewPathItem(
		"User resource operations",
		"Operations on a specific LDAP user",
		"Users",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = getUser(r.Context(), manager, w, r, cn)
		},
		"Get user",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/user/{cn}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid user name."),
		opts.WithErrorResponse(404, "User not found."),
	).Put(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = createUser(r.Context(), manager, w, r, cn)
		},
		"Create user",
		opts.WithDescription(doc.Section(3, "PUT /{prefix}/user/{cn}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPutRequest]()),
		opts.WithJSONResponse(201, nil),
		opts.WithErrorResponse(400, "Invalid user name or request body."),
		opts.WithErrorResponse(409, "User already exists."),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = updateUser(r.Context(), manager, w, r, cn)
		},
		"Update user",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/user/{cn}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPutRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid user name or request body."),
		opts.WithErrorResponse(404, "User not found."),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = deleteUser(r.Context(), manager, w, r, cn)
		},
		"Delete user",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/user/{cn}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid user name."),
		opts.WithErrorResponse(404, "User not found."),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listUsers(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.ObjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	users, err := manager.ListUsers(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), users)
}

func getUser(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	user, err := manager.GetUser(ctx, cn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), user)
}

func createUser(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req schema.ObjectPutRequest
	allocateGID := false
	if value := r.URL.Query().Get("allocate_gid"); value != "" {
		parsed, err := strconv.ParseBool(value)
		if err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid allocate_gid")
		}
		allocateGID = parsed
	}
	if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
		if err := httprequest.Read(r, &req); err != nil {
			if strings.Contains(err.Error(), "Missing request body") {
				req = schema.ObjectPutRequest{}
			} else {
				return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
			}
		}
	}
	user, err := manager.CreateUser(ctx, cn, req.Attrs, allocateGID)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), user)
}

func updateUser(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	user, err := manager.UpdateUser(ctx, cn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), user)
}

func deleteUser(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	user, err := manager.DeleteUser(ctx, cn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), user)
}
