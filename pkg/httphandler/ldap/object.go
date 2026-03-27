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
	"io"
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

func ObjectHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "object", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listObjects(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Object operations",
			Description: "Operations on LDAP objects",
			Get: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "List objects",
				Description: "Returns a filtered list of LDAP objects.",
				Parameters: []openapi.Parameter{
					{Name: "filter", In: openapi.ParameterInQuery, Description: "LDAP search filter.", Schema: jsonschema.MustFor[string]()},
					{Name: "attr", In: openapi.ParameterInQuery, Description: "Attributes to return. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of objects to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Object list.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectList]()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

func ObjectResourceHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	dnSchema := jsonschema.MustFor[string]()

	return "object/{dn}", func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}

			switch r.Method {
			case http.MethodGet:
				_ = getObject(r.Context(), manager, w, r, dn)
			case http.MethodPut:
				_ = createObject(r.Context(), manager, w, r, dn)
			case http.MethodPatch:
				_ = updateObject(r.Context(), manager, w, r, dn)
			case http.MethodDelete:
				_ = deleteObject(r.Context(), manager, w, r, dn)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Object operations",
			Description: "Operations on a specific LDAP object",
			Get: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "Get object",
				Description: "Returns a single LDAP object by distinguished name.",
				Parameters:  []openapi.Parameter{{Name: "dn", In: openapi.ParameterInPath, Description: "Distinguished name.", Required: true, Schema: dnSchema}},
				Responses: map[string]openapi.Response{
					"200": {Description: "Requested object."},
					"400": {Description: "Invalid distinguished name."},
					"404": {Description: "Object not found."},
				},
			},
			Put: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "Create object",
				Description: "Creates an LDAP object at the specified distinguished name.",
				Parameters:  []openapi.Parameter{{Name: "dn", In: openapi.ParameterInPath, Description: "Distinguished name.", Required: true, Schema: dnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "LDAP object attributes. The DN is taken from the path.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPutRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created object."},
					"400": {Description: "Invalid distinguished name or request body."},
					"409": {Description: "Object already exists."},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "Update object",
				Description: "Updates LDAP object attributes at the specified distinguished name.",
				Parameters:  []openapi.Parameter{{Name: "dn", In: openapi.ParameterInPath, Description: "Distinguished name.", Required: true, Schema: dnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "LDAP object attributes to replace or delete. Empty values delete an attribute.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPutRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated object."},
					"400": {Description: "Invalid distinguished name or request body."},
					"404": {Description: "Object not found."},
				},
			},
			Delete: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "Delete object",
				Description: "Deletes the LDAP object at the specified distinguished name.",
				Parameters:  []openapi.Parameter{{Name: "dn", In: openapi.ParameterInPath, Description: "Distinguished name.", Required: true, Schema: dnSchema}},
				Responses: map[string]openapi.Response{
					"204": {Description: "Deleted object."},
					"400": {Description: "Invalid distinguished name."},
					"404": {Description: "Object not found."},
				},
			},
		}
}

func ObjectBindHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	dnSchema := jsonschema.MustFor[string]()

	return "object/{dn}/bind", func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}

			switch r.Method {
			case http.MethodPost:
				_ = bindObject(r.Context(), manager, w, r, dn)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Object bind operations",
			Description: "Authentication operations for a specific LDAP object",
			Post: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "Bind object",
				Description: "Attempts to bind as the specified LDAP object using the supplied password.",
				Parameters:  []openapi.Parameter{{Name: "dn", In: openapi.ParameterInPath, Description: "Distinguished name.", Required: true, Schema: dnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Plaintext password for the LDAP bind operation.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"text/plain": {Schema: jsonschema.MustFor[string]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Bound object."},
					"400": {Description: "Invalid distinguished name or request body."},
					"401": {Description: "Invalid credentials."},
					"404": {Description: "Object not found."},
				},
			},
		}
}

func ObjectPasswordHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	dnSchema := jsonschema.MustFor[string]()

	return "object/{dn}/password", func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}

			switch r.Method {
			case http.MethodPost:
				_ = changePasswordObject(r.Context(), manager, w, r, dn)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Object password operations",
			Description: "Password management operations for a specific LDAP object",
			Post: &openapi.Operation{
				Tags:        []string{"Object"},
				Summary:     "Change object password",
				Description: "Changes the LDAP object password. If the new password is omitted, the server may generate one and return it in the response.",
				Parameters:  []openapi.Parameter{{Name: "dn", In: openapi.ParameterInPath, Description: "Distinguished name.", Required: true, Schema: dnSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Current password and optional new password.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.ObjectPasswordRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated object and optional generated password.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.PasswordResponse]()}}},
					"400": {Description: "Invalid distinguished name or request body."},
					"401": {Description: "Invalid credentials."},
					"404": {Description: "Object not found."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listObjects(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	// Decode the query parameters
	var req schema.ObjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	// List objects
	objects, err := manager.List(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the response
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), objects)
}

func objectPathDN(dn string) (string, error) {
	if dn == "" {
		return "", httpresponse.Err(http.StatusBadRequest).With("dn is required")
	} else if unescaped, err := url.PathUnescape(dn); err != nil {
		return "", httpresponse.Err(http.StatusBadRequest).With(err.Error())
	} else {
		return unescaped, nil
	}
}

func getObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	object, err := manager.Get(ctx, dn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}

func createObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	object, err := manager.Create(ctx, dn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), object)
}

func updateObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	object, err := manager.Update(ctx, dn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}

func bindObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	password, err := io.ReadAll(r.Body)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	object, err := manager.Bind(ctx, dn, string(password))
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}

func changePasswordObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	var req schema.ObjectPasswordRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	old := strings.TrimSpace(req.Old)
	var newPassword *string
	if req.New != nil {
		if trimmed := strings.TrimSpace(*req.New); trimmed != "" {
			newPassword = &trimmed
		}
	}
	object, generatedPassword, err := manager.ChangePassword(ctx, dn, old, newPassword)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object.WithPassword(generatedPassword))
}

func deleteObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, _ *http.Request, dn string) error {
	if _, err := manager.Delete(ctx, dn); err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.Empty(w, http.StatusNoContent)
}
