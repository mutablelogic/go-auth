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
	"net/http"

	// Packages
	autherr "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// HANDLER METHODS

func ConfigHandler(manager *manager.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "config", nil, httprequest.NewPathItem(
		"Public provider configuration",
		docBody(doc, 2, "Auth", "Returns the upstream provider details that are safe to expose to clients that need to start an authentication flow."),
		"Auth",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			config, err := manager.AuthConfig(r.Context())
			if err != nil {
				_ = httpresponse.Error(w, autherr.HTTPError(err))
				return
			}
			_ = httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
		},
		"Get public auth configuration",
		opts.WithDescription(doc.Section(3, "GET /config").Body),
		opts.WithJSONResponse(http.StatusOK, jsonschema.MustFor[schema.PublicClientConfigurations]()),
		opts.WithErrorResponse(http.StatusNotFound, "No upstream providers are configured."),
	)
}
