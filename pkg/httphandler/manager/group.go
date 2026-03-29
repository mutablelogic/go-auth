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

	// Packages
	coremanager "github.com/djthorpe/go-auth/pkg/authmanager"
	schema "github.com/djthorpe/go-auth/schema/auth"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// GroupHandler returns an http.HandlerFunc for the group endpoint.
func GroupHandler(mgr *coremanager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "group", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = createGroup(r.Context(), mgr, w, r)
			case http.MethodGet:
				_ = listGroup(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Group operations",
			Description: "Operations on groups",
			Get: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "List groups",
				Description: "Returns a paginated list of groups.",
				Parameters: []openapi.Parameter{
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of groups to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Group list.", Content: map[string]openapi.MediaType{"application/json": {Schema: groupListSchema()}}},
					"400": {Description: "Invalid pagination parameters."},
				},
			},
			Post: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "Create group",
				Description: "Creates a new group.",
				RequestBody: &openapi.RequestBody{
					Description: "Group fields for the new group.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.GroupInsert]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created group.", Content: map[string]openapi.MediaType{"application/json": {Schema: groupSchema()}}},
					"400": {Description: "Invalid request body or group creation failure."},
				},
			},
		}
}

// GroupItemHandler returns an http.HandlerFunc for a specific group endpoint.
func GroupItemHandler(mgr *coremanager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	groupIDSchema := jsonschema.MustFor[string]()

	return "group/{group}", func(w http.ResponseWriter, r *http.Request) {
			group := r.PathValue("group")
			if group == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "group is required")
				return
			}

			switch r.Method {
			case http.MethodGet:
				_ = getGroup(r.Context(), mgr, w, r, group)
			case http.MethodPatch:
				_ = updateGroup(r.Context(), mgr, w, r, group)
			case http.MethodDelete:
				_ = deleteGroup(r.Context(), mgr, w, r, group)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Group operations",
			Description: "Operations on a specific group",
			Get: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "Get group",
				Description: "Returns a single group by identifier.",
				Parameters:  []openapi.Parameter{{Name: "group", In: openapi.ParameterInPath, Description: "Group identifier.", Required: true, Schema: groupIDSchema}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Requested group.", Content: map[string]openapi.MediaType{"application/json": {Schema: groupSchema()}}},
					"400": {Description: "Invalid group identifier."},
					"404": {Description: "Group not found."},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "Update group",
				Description: "Updates mutable fields on a group.",
				Parameters:  []openapi.Parameter{{Name: "group", In: openapi.ParameterInPath, Description: "Group identifier.", Required: true, Schema: groupIDSchema}},
				RequestBody: &openapi.RequestBody{Description: "Group fields to update.", Required: true, Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.GroupMeta]()}}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated group.", Content: map[string]openapi.MediaType{"application/json": {Schema: groupSchema()}}},
					"400": {Description: "Invalid group identifier or request body."},
					"404": {Description: "Group not found."},
				},
			},
			Delete: &openapi.Operation{
				Tags:        []string{"Group"},
				Summary:     "Delete group",
				Description: "Deletes a group by identifier.",
				Parameters:  []openapi.Parameter{{Name: "group", In: openapi.ParameterInPath, Description: "Group identifier.", Required: true, Schema: groupIDSchema}},
				Responses: map[string]openapi.Response{
					"204": {Description: "Group deleted."},
					"400": {Description: "Invalid group identifier."},
					"404": {Description: "Group not found."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createGroup(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.GroupInsert
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	group, err := mgr.CreateGroup(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), group)
}

func listGroup(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.GroupListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	groups, err := mgr.ListGroups(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), groups)
}

func getGroup(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, r *http.Request, group string) error {
	response, err := mgr.GetGroup(ctx, group)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func updateGroup(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, r *http.Request, group string) error {
	var req schema.GroupMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	response, err := mgr.UpdateGroup(ctx, group, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func deleteGroup(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, _ *http.Request, group string) error {
	_, err := mgr.DeleteGroup(ctx, group)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.Empty(w, http.StatusNoContent)
}
