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
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// CertHandler returns a path and pathitem for the certificate list endpoint.
func CertHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "cert", nil, httprequest.NewPathItem(
		"Certificate operations",
		"Operations on managed certificates.",
		"Certificate",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listCerts(r.Context(), manager, w, r)
		},
		"List certificates",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/cert").Body),
		opts.WithQuery(jsonschema.MustFor[schema.CertListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.CertList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
	)
}

// CertByCAHandler returns a path and pathitem for certificate operations by name.
func CertByCAHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "cert/{name}", nil, httprequest.NewPathItem(
		"Certificate operations by name",
		"Fetches the latest certificate version by name or creates a leaf certificate signed by the latest certificate authority version with that name.",
		"Certificate",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = getCertByName(r.Context(), manager, w, r, r.PathValue("name"))
		},
		"Get latest certificate",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/cert/{name}").Body),
		opts.WithQuery(jsonschema.MustFor[certQuery]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.CertBundle]()),
		opts.WithErrorResponse(400, "Invalid certificate name or query parameters."),
		opts.WithErrorResponse(404, "Certificate not found."),
		opts.WithErrorResponse(409, "Certificate is disabled."),
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = createCertByCAName(r.Context(), manager, w, r, r.PathValue("name"))
		},
		"Create certificate from CA name",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/cert/{name}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.CreateCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate authority name or request body."),
		opts.WithErrorResponse(404, "Signing certificate authority was not found."),
		opts.WithErrorResponse(409, "Certificate already exists or signing certificate authority state prevents issuance."),
		opts.WithErrorResponse(503, "Certificate issuance is not available because server certificate prerequisites are not configured."),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			_ = updateCertByName(r.Context(), manager, w, r, r.PathValue("name"))
		},
		"Update latest certificate",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/cert/{name}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.CertMeta]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate name or request body."),
		opts.WithErrorResponse(404, "Certificate not found."),
	)
}

// CertByCAKeyHandler returns a path and pathitem for certificate operations by version.
func CertByCAKeyHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "cert/{name}/{serial}", nil, httprequest.NewPathItem(
		"Certificate operations by version",
		"Fetches a specific certificate version or creates a leaf certificate signed by a specific certificate authority version.",
		"Certificate",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = getCertByKey(r.Context(), manager, w, r, schema.CertKey{Name: r.PathValue("name"), Serial: r.PathValue("serial")})
		},
		"Get certificate by version",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/cert/{name}/{serial}").Body),
		opts.WithQuery(jsonschema.MustFor[certQuery]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.CertBundle]()),
		opts.WithErrorResponse(400, "Invalid certificate key or query parameters."),
		opts.WithErrorResponse(404, "Certificate not found."),
		opts.WithErrorResponse(409, "Certificate is disabled."),
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = createCert(r.Context(), manager, w, r, schema.CertKey{Name: r.PathValue("name"), Serial: r.PathValue("serial")})
		},
		"Create certificate from CA version",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/cert/{name}/{serial}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.CreateCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate authority key or request body."),
		opts.WithErrorResponse(404, "Signing certificate authority was not found."),
		opts.WithErrorResponse(409, "Certificate already exists or signing certificate authority state prevents issuance."),
		opts.WithErrorResponse(503, "Certificate issuance is not available because server certificate prerequisites are not configured."),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			_ = updateCertByKey(r.Context(), manager, w, r, schema.CertKey{Name: r.PathValue("name"), Serial: r.PathValue("serial")})
		},
		"Update certificate by version",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/cert/{name}/{serial}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.CertMeta]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate key or request body."),
		opts.WithErrorResponse(404, "Certificate not found."),
	)
}

// CertRenewByNameHandler returns a path and pathitem for renewing the latest certificate version with the provided name.
func CertRenewByNameHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "cert/{name}/renew", nil, httprequest.NewPathItem(
		"Certificate renewal by name",
		"Renews the latest certificate version with the supplied name.",
		"Certificate",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = renewCertByName(r.Context(), manager, w, r, r.PathValue("name"))
		},
		"Renew latest certificate",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/cert/{name}/renew").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.RenewCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate name or request body."),
		opts.WithErrorResponse(404, "Certificate not found."),
		opts.WithErrorResponse(409, "Certificate or signer state prevents renewal."),
		opts.WithErrorResponse(503, "Certificate renewal is not available because server certificate prerequisites are not configured."),
	)
}

// CertRenewByKeyHandler returns a path and pathitem for renewing an explicit certificate version.
func CertRenewByKeyHandler(manager *managerpkg.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "cert/{name}/{serial}/renew", nil, httprequest.NewPathItem(
		"Certificate renewal by version",
		"Renews the specified certificate version.",
		"Certificate",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			_ = renewCertByKey(r.Context(), manager, w, r, schema.CertKey{Name: r.PathValue("name"), Serial: r.PathValue("serial")})
		},
		"Renew certificate by version",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/cert/{name}/{serial}/renew").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.RenewCertRequest]()),
		opts.WithJSONResponse(201, jsonschema.MustFor[schema.Cert]()),
		opts.WithErrorResponse(400, "Invalid certificate key or request body."),
		opts.WithErrorResponse(404, "Certificate not found."),
		opts.WithErrorResponse(409, "Certificate or signer state prevents renewal."),
		opts.WithErrorResponse(503, "Certificate renewal is not available because server certificate prerequisites are not configured."),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

type certQuery struct {
	Chain   *bool `json:"chain,omitempty"`
	Private *bool `json:"private,omitempty"`
}

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

func getCertByName(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, name string) error {
	var query certQuery
	if err := httprequest.Query(r.URL.Query(), &query); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	bundle, err := certBundleByName(ctx, manager, name, types.Value(query.Chain), types.Value(query.Private))
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), bundle)
}

func getCertByKey(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, key schema.CertKey) error {
	var query certQuery
	if err := httprequest.Query(r.URL.Query(), &query); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	bundle, err := certBundleByKey(ctx, manager, key, types.Value(query.Chain), types.Value(query.Private))
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), bundle)
}

func createCertByCAName(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, caName string) error {
	var req schema.CreateCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	var caRow schema.Cert
	if err := manager.Get(ctx, &caRow, schema.CertName(caName)); err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	cert, err := manager.CreateCert(ctx, req, caRow.CertKey)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), cert)
}

func updateCertByName(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, name string) error {
	var req schema.CertMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	var certRow schema.Cert
	if err := manager.Get(ctx, &certRow, schema.CertName(name)); err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return updateCertMeta(ctx, manager, w, r, certRow.CertKey, req)
}

func updateCertByKey(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, key schema.CertKey) error {
	var req schema.CertMeta
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	return updateCertMeta(ctx, manager, w, r, key, req)
}

func renewCertByName(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, name string) error {
	var req schema.RenewCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	var certRow schema.Cert
	if err := manager.Get(ctx, &certRow, schema.CertName(name)); err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	renewed, err := manager.RenewCert(ctx, certRow.CertKey, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), renewed)
}

func renewCertByKey(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, key schema.CertKey) error {
	var req schema.RenewCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	renewed, err := manager.RenewCert(ctx, key, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), renewed)
}

func certBundleByName(ctx context.Context, manager *managerpkg.Manager, name string, chain bool, private bool) (*schema.CertBundle, error) {
	var certRow schema.Cert
	if err := manager.Get(ctx, &certRow, schema.CertName(name)); err != nil {
		return nil, err
	}
	return certBundleByKey(ctx, manager, certRow.CertKey, chain, private)
}

func certBundleByKey(ctx context.Context, manager *managerpkg.Manager, key schema.CertKey, chain bool, private bool) (*schema.CertBundle, error) {
	bundle := new(schema.CertBundle)
	if private {
		certRow, err := manager.GetPrivateKey(ctx, key)
		if err != nil {
			return nil, err
		}
		bundle.Cert = certRow.Cert
		bundle.Key = certRow.Key
	} else if err := manager.Get(ctx, &bundle.Cert, key); err != nil {
		return nil, err
	}
	if !types.Value(bundle.Cert.Enabled) {
		return nil, httpresponse.ErrConflict.With("certificate is disabled")
	}

	if chain {
		certChain, err := manager.GetCertChain(ctx, bundle.CertKey)
		if err != nil {
			return nil, err
		}
		bundle.Chain = issuerChain(bundle.CertKey, certChain)
	}

	return bundle, nil
}

func issuerChain(selected schema.CertKey, chain []schema.Cert) []schema.Cert {
	if len(chain) == 0 {
		return nil
	}
	if chain[0].CertKey == selected {
		chain = chain[1:]
	}
	if len(chain) == 0 {
		return nil
	}
	return append([]schema.Cert(nil), chain...)
}

func createCert(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, signer schema.CertKey) error {
	var req schema.CreateCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}

	cert, err := manager.CreateCert(ctx, req, signer)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), cert)
}

func updateCertMeta(ctx context.Context, manager *managerpkg.Manager, w http.ResponseWriter, r *http.Request, key schema.CertKey, req schema.CertMeta) error {
	cert, err := manager.UpdateCert(ctx, key, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), cert)
}
