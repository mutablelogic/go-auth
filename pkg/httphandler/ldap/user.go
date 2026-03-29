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
	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func UserHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "user", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listUsers(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "User operations",
			Description: "Operations on LDAP users",
			Get: &openapi.Operation{
				Tags:        []string{"Users"},
				Summary:     "List users",
				Description: "Returns a paginated list of LDAP users.",
				Parameters: []openapi.Parameter{
					{Name: "filter", In: openapi.ParameterInQuery, Description: "LDAP filter expression.", Schema: jsonschema.MustFor[string]()},
					{Name: "attr", In: openapi.ParameterInQuery, Description: "Attributes to return. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of users to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "User list.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectList]()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

func UserResourceHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	cnSchema := jsonschema.MustFor[string]()

	return "user/{cn}", func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			switch r.Method {
			case http.MethodGet:
				_ = getUser(r.Context(), manager, w, r, cn)
			case http.MethodPut:
				_ = createUser(r.Context(), manager, w, r, cn)
			case http.MethodPatch:
				_ = updateUser(r.Context(), manager, w, r, cn)
			case http.MethodDelete:
				_ = deleteUser(r.Context(), manager, w, r, cn)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "User resource operations",
			Description: "Operations on a specific LDAP user",
			Get: &openapi.Operation{
				Tags:        []string{"Users"},
				Summary:     "Get user",
				Description: "Returns a single LDAP user by name.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "User name.", Required: true, Schema: cnSchema}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Requested user.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Object]()}}},
					"400": {Description: "Invalid user name."},
					"404": {Description: "User not found."},
				},
			},
			Put: &openapi.Operation{
				Tags:        []string{"Users"},
				Summary:     "Create user",
				Description: "Creates a new LDAP user with the given name.",
				Parameters: []openapi.Parameter{
					{Name: "cn", In: openapi.ParameterInPath, Description: "User name.", Required: true, Schema: cnSchema},
					{Name: "allocate_gid", In: openapi.ParameterInQuery, Description: "When true, set gidNumber to the effective uidNumber if gidNumber is omitted.", Schema: jsonschema.MustFor[bool]()},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Additional user attributes.",
					Required:    false,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPutRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created user."},
					"400": {Description: "Invalid user name or request body."},
					"409": {Description: "User already exists."},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"Users"},
				Summary:     "Update user",
				Description: "Updates LDAP user attributes for the specified name. If the user naming attribute changes, the entry is renamed first.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "User name.", Required: true, Schema: cnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "LDAP user attributes to replace or delete. Empty values delete an attribute.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPutRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated user.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Object]()}}},
					"400": {Description: "Invalid user name or request body."},
					"404": {Description: "User not found."},
				},
			},
			Delete: &openapi.Operation{
				Tags:        []string{"Users"},
				Summary:     "Delete user",
				Description: "Deletes the LDAP user with the given name.",
				Parameters:  []openapi.Parameter{{Name: "cn", In: openapi.ParameterInPath, Description: "User name.", Required: true, Schema: cnSchema}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Deleted user.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Object]()}}},
					"400": {Description: "Invalid user name."},
					"404": {Description: "User not found."},
				},
			},
		}
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
