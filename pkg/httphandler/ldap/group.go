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
	"strings"

	// Packages
	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func GroupHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "group", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listGroups(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Group operations",
			Description: "Operations on LDAP groups",
			Get: &openapi.Operation{
				Tags:        []string{"Groups"},
				Summary:     "List groups",
				Description: "Returns a paginated list of LDAP groups.",
				Parameters: []openapi.Parameter{
					{Name: "filter", In: openapi.ParameterInQuery, Description: "LDAP filter expression.", Schema: jsonschema.MustFor[string]()},
					{Name: "attr", In: openapi.ParameterInQuery, Description: "Attributes to return. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of groups to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Group list.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectList]()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

func GroupResourceHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	cnSchema := jsonschema.MustFor[string]()

	return "group/{cn}", func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			switch r.Method {
			case http.MethodGet:
				_ = getGroup(r.Context(), manager, w, r, cn)
			case http.MethodPut:
				_ = createGroup(r.Context(), manager, w, r, cn)
			case http.MethodPatch:
				_ = updateGroup(r.Context(), manager, w, r, cn)
			case http.MethodDelete:
				_ = deleteGroup(r.Context(), manager, w, r, cn)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Group resource operations",
			Description: "Operations on a specific LDAP group",
			Get: &openapi.Operation{
				Tags:        []string{"Groups"},
				Summary:     "Get group",
				Description: "Returns a single LDAP group by common name.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "Group common name.", Required: true, Schema: cnSchema}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Requested group.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Object]()}}},
					"400": {Description: "Invalid common name."},
					"404": {Description: "Group not found."},
				},
			},
			Put: &openapi.Operation{
				Tags:        []string{"Groups"},
				Summary:     "Create group",
				Description: "Creates a new LDAP group with the given common name.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "Group common name.", Required: true, Schema: cnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Additional group attributes.",
					Required:    false,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPutRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created group."},
					"400": {Description: "Invalid common name or request body."},
					"409": {Description: "Group already exists."},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"Groups"},
				Summary:     "Update group",
				Description: "Updates LDAP group attributes for the specified common name. If the group naming attribute changes, the entry is renamed first.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "Group common name.", Required: true, Schema: cnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "LDAP group attributes to replace or delete. Empty values delete an attribute.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPutRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated group.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Object]()}}},
					"400": {Description: "Invalid common name or request body."},
					"404": {Description: "Group not found."},
				},
			},
			Delete: &openapi.Operation{
				Tags:        []string{"Groups"},
				Summary:     "Delete group",
				Description: "Deletes the LDAP group with the given common name.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "Group common name.", Required: true, Schema: cnSchema}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Deleted group.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Object]()}}},
					"400": {Description: "Invalid common name."},
					"404": {Description: "Group not found."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listGroups(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.ObjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	groups, err := manager.ListGroups(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), groups)
}

func getGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	group, err := manager.GetGroup(ctx, cn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}

func createGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req schema.ObjectPutRequest
	if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
		if err := httprequest.Read(r, &req); err != nil {
			if strings.Contains(err.Error(), "Missing request body") {
				req = schema.ObjectPutRequest{}
			} else {
				return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
			}
		}
	}
	group, err := manager.CreateGroup(ctx, cn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), group)
}

func updateGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	group, err := manager.UpdateGroup(ctx, cn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}

func deleteGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	group, err := manager.DeleteGroup(ctx, cn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}
