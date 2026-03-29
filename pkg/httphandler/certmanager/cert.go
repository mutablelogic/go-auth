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

package certmanager

import (
	"context"
	"net/http"

	// Packages
	managerpkg "github.com/djthorpe/go-auth/pkg/certmanager"
	schema "github.com/djthorpe/go-auth/schema/cert"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CertHandler returns an http.HandlerFunc for the certificate list endpoint.
func CertHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "cert", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listCerts(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate operations",
			Description: "Operations on managed certificates.",
			Get: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "List certificates",
				Description: "Returns a paginated list of non-root certificates, optionally filtered by effective state and tags.",
				Parameters: []openapi.Parameter{
					{Name: "is_ca", In: openapi.ParameterInQuery, Description: "Filter certificate authorities or leaf certificates.", Schema: jsonschema.MustFor[bool]()},
					{Name: "enabled", In: openapi.ParameterInQuery, Description: "Filter by effective enabled state.", Schema: jsonschema.MustFor[bool]()},
					{Name: "tags", In: openapi.ParameterInQuery, Description: "Require all effective tags. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "valid", In: openapi.ParameterInQuery, Description: "Filter by current validity window.", Schema: jsonschema.MustFor[bool]()},
					{Name: "subject", In: openapi.ParameterInQuery, Description: "Filter by subject row identifier.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of certificates to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Certificate list.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CertList]()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listCerts(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.CertListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	certs, err := manager.ListCerts(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), certs)
}
