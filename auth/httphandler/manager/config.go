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
	authpkg "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	markdown "github.com/mutablelogic/go-auth/pkg/markdown"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ConfigHandler(mgr *manager.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "config", nil, httprequest.NewPathItem(
		"Public configuration",
		"Returns the upstream authentication provider details that are safe to expose to clients.",
		"Configuration",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = GetAuthConfig(r.Context(), mgr, w, r)
		},
		"Get configuration",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/config").Body),
		opts.WithJSONResponse(200, nil),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func GetAuthConfig(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.AuthConfig()
	if err != nil {
		return httpresponse.Error(w, authpkg.HTTPError(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}
