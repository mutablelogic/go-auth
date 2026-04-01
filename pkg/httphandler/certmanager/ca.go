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
	markdown "github.com/djthorpe/go-auth/pkg/markdown"
	schema "github.com/djthorpe/go-auth/schema/cert"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CAHandler returns a path and pathitem for certificate authority creation that can be used for dynamic registration.
func CAHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "ca", nil, httprequest.NewPathItem(
		"Certificate authority operations",               // Summary
		"Operations on managed certificate authorities.", // Description
		"Certificate Authority",                          // Tags
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = createCA(r.Context(), manager, w, r)
		},
		"Create a certificate authority",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/ca").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.CreateCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid request body or certificate authority parameters."),
		opts.WithErrorResponse(409, "Certificate authority already exists or root certificate state prevents issuance."),
		opts.WithErrorResponse(503, "Certificate issuance is not available because server certificate prerequisites are not configured."),
	)
}

// CAByNameRenewHandler returns a path and pathitem for renewing the latest CA version with the provided name.
func CAByNameRenewHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "ca/{name}/renew", nil, httprequest.NewPathItem(
		"Certificate authority renewal by name",
		"Renews the latest certificate authority version with the supplied name.",
		"Certificate Authority",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = renewCAByName(r.Context(), manager, w, r, r.PathValue("name"))
		},
		"Renew latest certificate authority",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/ca/{name}/renew").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.RenewCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate authority name or request body."),
		opts.WithErrorResponse(404, "Certificate authority not found."),
		opts.WithErrorResponse(409, "Certificate authority or root state prevents renewal."),
		opts.WithErrorResponse(503, "Certificate renewal is not available because server certificate prerequisites are not configured."),
	)
}

// CAByKeyRenewHandler returns a path and pathitem for renewing an explicit CA version.
func CAByKeyRenewHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "ca/{name}/{serial}/renew", nil, httprequest.NewPathItem(
		"Certificate authority renewal by version",
		"Renews the specified certificate authority version.",
		"Certificate Authority",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = renewCAByKey(r.Context(), manager, w, r, schema.CertKey{Name: r.PathValue("name"), Serial: r.PathValue("serial")})
		},
		"Renew certificate authority by version",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/ca/{name}/{serial}/renew").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.RenewCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate authority key or request body."),
		opts.WithErrorResponse(404, "Certificate authority not found."),
		opts.WithErrorResponse(409, "Certificate authority or root state prevents renewal."),
		opts.WithErrorResponse(503, "Certificate renewal is not available because server certificate prerequisites are not configured."),
	)
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
