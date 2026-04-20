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
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// KeyHandler returns a path and pathitem for the key endpoint.
func KeyHandler(manager *manager.Manager, auth bool, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "key", nil, httprequest.NewPathItem(
		"Key operations",
		docBody(doc, 2, "API Keys", "Operations on API keys"),
		"API Keys",
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

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createKey(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	// Get the user
	user := middleware.UserFromContext(ctx)
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized), "Unauthorized")
	}

	// Get the request
	var req schema.KeyMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	// Create the key
	key, err := manager.CreateKey(ctx, user.ID, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}

	// Return the key
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), key)
}
