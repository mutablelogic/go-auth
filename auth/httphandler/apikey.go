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
	middleware "github.com/mutablelogic/go-auth/auth/middleware"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// KeyHandler returns a path and pathitem for the key endpoint.
func KeyHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "key", nil, httprequest.NewPathItem(
		"Key operations",
		docBody(doc, 2, "API Key", "Operations on API keys"),
		"API Key",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listKey(r.Context(), manager, w, r)
		},
		"List keys",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/key").Body),
		opts.WithQuery(jsonschema.MustFor[schema.KeyListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.KeyList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthKeyRead),
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = createKey(r.Context(), manager, w, r)
		},
		"Create key",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/key").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.KeyMeta]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Key]()),
		opts.WithErrorResponse(400, "Invalid request body or API key creation failure."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthKeyWrite),
	)
}

// KeyResourceHandler returns a path and pathitem for the key resource endpoint.
func KeyResourceHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "key/{key}", nil, httprequest.NewPathItem(
		"Key operations",
		docBody(doc, 2, "API Key", "Operations on API keys"),
		"API Key",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			key, err := schema.KeyIDFromString(r.PathValue("key"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = getKey(r.Context(), manager, w, r, key)
		},
		"Get key",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/key/{key}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Key]()),
		opts.WithErrorResponse(400, "Invalid API key identifier."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthKeyRead),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			key, err := schema.KeyIDFromString(r.PathValue("key"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = updateKey(r.Context(), manager, w, r, key)
		},
		"Update key",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/key/{key}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.KeyMeta]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Key]()),
		opts.WithErrorResponse(400, "Invalid API key identifier or request body."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthKeyRead, schema.ScopeAuthKeyWrite),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			key, err := schema.KeyIDFromString(r.PathValue("key"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = deleteKey(r.Context(), manager, w, r, key)
		},
		"Delete key",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/key/{key}").Body),
		opts.WithErrorResponse(400, "Invalid API key identifier."),
		opts.WithSecurity(schema.SecurityBearerAuth, auth, schema.ScopeAuthKeyWrite),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listKey(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	user := middleware.UserFromContext(ctx)
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized))
	}

	// Get the query parameters
	var req schema.KeyListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// List the keys
	keys, err := manager.ListKeys(ctx, &user.Sub, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}

	// Return the keys
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), keys)
}

func createKey(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	// Get the user
	user := middleware.UserFromContext(ctx)
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized))
	}

	// Get the request
	var req schema.KeyMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// Create the key
	key, err := manager.CreateKey(ctx, user.Sub, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}

	// Return the key
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), key)
}

func getKey(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, key schema.KeyID) error {
	// Get the user
	user := middleware.UserFromContext(ctx)
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized))
	}

	// Get the API key
	response, err := manager.GetKeyByID(ctx, key, types.Ptr(user.Sub))
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}

	// Return the API key
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func updateKey(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request, key schema.KeyID) error {
	// Get the user
	user := middleware.UserFromContext(ctx)
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized))
	}

	// Get the request
	var req schema.KeyMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// Update the API key
	response, err := manager.UpdateKey(ctx, key, types.Ptr(user.Sub), req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}

	// Return the API key
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), response)
}

func deleteKey(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, _ *http.Request, key schema.KeyID) error {
	// Get the user
	user := middleware.UserFromContext(ctx)
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized))
	}

	// Delete the API key
	_, err := manager.DeleteKey(ctx, key, types.Ptr(user.Sub))
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}

	// Return success
	return httpresponse.Empty(w, http.StatusNoContent)
}
