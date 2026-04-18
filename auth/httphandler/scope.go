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

// ScopeHandler returns a path and pathitem for the scope endpoint.
func ScopeHandler(manager *manager.Manager, auth func(http.HandlerFunc) http.HandlerFunc, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "scope", nil, httprequest.NewPathItem(
		"Scope operations",
		"Operations on scopes",
		"Scope",
	).Get(
		auth(func(w http.ResponseWriter, r *http.Request) {
			_ = listScope(r.Context(), manager, w, r)
		}),
		"List scopes",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/scope").Body),
		opts.WithQuery(jsonschema.MustFor[schema.ScopeListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.ScopeList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
		opts.WithSecurity(schema.SecurityBearerAuth, schema.ScopeAuthGroupRead),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listScope(ctx context.Context, manager *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.ScopeListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	scopes, err := manager.ListScopes(ctx, req)
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), scopes)
}
