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

// CAHandler returns an http.HandlerFunc for certificate authority creation.
func CAHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "ca", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodPost:
				_ = createCA(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate authority operations",
			Description: "Operations on managed certificate authorities.",
			Post: &openapi.Operation{
				Tags:        []string{"Certificate Authority"},
				Summary:     "Create certificate authority",
				Description: "Creates a new certificate authority signed by the configured root certificate.",
				RequestBody: &openapi.RequestBody{
					Description: "Certificate authority fields for the new certificate.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CreateCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created certificate authority.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid request body or certificate authority parameters."},
					"409": {Description: "Certificate authority already exists or root certificate state prevents issuance."},
					"503": {Description: "Certificate issuance is not available because server certificate prerequisites are not configured."},
				},
			},
		}
}

// CAByNameRenewHandler returns an http.HandlerFunc for renewing the latest CA version with the provided name.
func CAByNameRenewHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	nameSchema := jsonschema.MustFor[string]()

	return "ca/{name}/renew", func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			if name == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "name is required")
				return
			}

			switch r.Method {
			case http.MethodPost:
				_ = renewCAByName(r.Context(), manager, w, r, name)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate authority renewal by name",
			Description: "Renews the latest certificate authority version with the supplied name.",
			Post: &openapi.Operation{
				Tags:        []string{"Certificate Authority"},
				Summary:     "Renew latest certificate authority",
				Description: "Creates a new certificate authority version from the latest certificate authority with the supplied name and disables the previous version.",
				Parameters:  []openapi.Parameter{{Name: "name", In: openapi.ParameterInPath, Description: "Certificate authority name.", Required: true, Schema: nameSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Certificate authority renewal fields for the new certificate version.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.RenewCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Renewed certificate authority.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate authority name or request body."},
					"404": {Description: "Certificate authority not found."},
					"409": {Description: "Certificate authority or root state prevents renewal."},
					"503": {Description: "Certificate renewal is not available because server certificate prerequisites are not configured."},
				},
			},
		}
}

// CAByKeyRenewHandler returns an http.HandlerFunc for renewing an explicit CA version.
func CAByKeyRenewHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	nameSchema := jsonschema.MustFor[string]()
	serialSchema := jsonschema.MustFor[string]()

	return "ca/{name}/{serial}/renew", func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			serial := r.PathValue("serial")
			if name == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "name is required")
				return
			}
			if serial == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "serial is required")
				return
			}

			switch r.Method {
			case http.MethodPost:
				_ = renewCAByKey(r.Context(), manager, w, r, schema.CertKey{Name: name, Serial: serial})
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate authority renewal by version",
			Description: "Renews the specified certificate authority version.",
			Post: &openapi.Operation{
				Tags:        []string{"Certificate Authority"},
				Summary:     "Renew certificate authority by version",
				Description: "Creates a new certificate authority version from the requested certificate authority name and serial number and disables the previous version.",
				Parameters: []openapi.Parameter{
					{Name: "name", In: openapi.ParameterInPath, Description: "Certificate authority name.", Required: true, Schema: nameSchema},
					{Name: "serial", In: openapi.ParameterInPath, Description: "Certificate authority serial number.", Required: true, Schema: serialSchema},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Certificate authority renewal fields for the new certificate version.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.RenewCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Renewed certificate authority.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate authority key or request body."},
					"404": {Description: "Certificate authority not found."},
					"409": {Description: "Certificate authority or root state prevents renewal."},
					"503": {Description: "Certificate renewal is not available because server certificate prerequisites are not configured."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func createCA(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.CreateCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	ca, err := manager.CreateCA(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), ca)
}

func renewCAByName(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, name string) error {
	var req schema.RenewCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	var certRow schema.Cert
	if err := manager.Get(ctx, &certRow, schema.CertName(name)); err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	renewed, err := manager.RenewCA(ctx, certRow.CertKey, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), renewed)
}

func renewCAByKey(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, key schema.CertKey) error {
	var req schema.RenewCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	renewed, err := manager.RenewCA(ctx, key, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), renewed)
}
