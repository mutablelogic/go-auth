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

// GroupHandler returns a path and pathitem for the group collection endpoint.
func GroupHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "group", nil, httprequest.NewPathItem(
		"Group operations",
		"Operations on groups",
		"Group",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listGroup(r.Context(), manager, w, r)
		},
		"List groups",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/group").Body),
		opts.WithQuery(jsonschema.MustFor[schema.GroupListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.GroupList]()),
		opts.WithErrorResponse(400, "Invalid pagination parameters."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthGroupRead),
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = createGroup(r.Context(), manager, w, r)
		},
		"Create group",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/group").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.GroupInsert]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Group]()),
		opts.WithErrorResponse(400, "Invalid request body or group creation failure."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthGroupRead, schema.ScopeAuthGroupWrite),
	)
}

// GroupItemHandler returns a path and pathitem for the group resource endpoint.
func GroupItemHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "group/{group}", nil, httprequest.NewPathItem(
		"Group operations",
		"Operations on a specific group",
		"Group",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			group := r.PathValue("group")
			if group == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "group is required")
				return
			}
			_ = getGroup(r.Context(), manager, w, r, group)
		},
		"Get group",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/group/{group}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Group]()),
		opts.WithErrorResponse(400, "Invalid group identifier."),
		opts.WithErrorResponse(404, "Group not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthGroupRead),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			group := r.PathValue("group")
			if group == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "group is required")
				return
			}
			_ = updateGroup(r.Context(), manager, w, r, group)
		},
		"Update group",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/group/{group}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.GroupMeta]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Group]()),
		opts.WithErrorResponse(400, "Invalid group identifier or request body."),
		opts.WithErrorResponse(404, "Group not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthGroupRead, schema.ScopeAuthGroupWrite),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			group := r.PathValue("group")
			if group == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "group is required")
				return
			}
			_ = deleteGroup(r.Context(), manager, w, r, group)
		},
		"Delete group",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/group/{group}").Body),
		opts.WithErrorResponse(400, "Invalid group identifier."),
		opts.WithErrorResponse(404, "Group not found."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthGroupWrite),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.GroupInsert
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	group, err := mgr.CreateGroup(ctx, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), group)
}

func listGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.GroupListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	groups, err := mgr.ListGroups(ctx, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), groups)
}

func getGroup(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request, group string) error {
	response, err := mgr.GetGroup(ctx, group)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func updateGroup(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, group string) error {
	var req schema.GroupMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	response, err := manager.UpdateGroup(ctx, group, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func deleteGroup(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, _ *http.Request, group string) error {
	_, err := manager.DeleteGroup(ctx, group)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.Empty(w, http.StatusNoContent)
}
