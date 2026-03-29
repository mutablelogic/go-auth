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
	types "github.com/mutablelogic/go-server/pkg/types"
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

// CertByCAHandler returns an http.HandlerFunc for creating a certificate signed by the latest CA version with the provided name.
func CertByCAHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	nameSchema := jsonschema.MustFor[string]()
	querySchema := jsonschema.MustFor[bool]()

	return "cert/{name}", func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			if name == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "name is required")
				return
			}

			switch r.Method {
			case http.MethodGet:
				_ = getCertByName(r.Context(), manager, w, r, name)
			case http.MethodPatch:
				_ = updateCertByName(r.Context(), manager, w, r, name)
			case http.MethodPost:
				_ = createCertByCAName(r.Context(), manager, w, r, name)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate operations by name",
			Description: "Fetches the latest certificate version by name or creates a leaf certificate signed by the latest certificate authority version with that name.",
			Get: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Get latest certificate",
				Description: "Returns the latest certificate version for the supplied name. Use query parameters to include issuer-chain certificates and the decrypted private key where available.",
				Parameters: []openapi.Parameter{
					{Name: "name", In: openapi.ParameterInPath, Description: "Certificate name.", Required: true, Schema: nameSchema},
					{Name: "chain", In: openapi.ParameterInQuery, Description: "Include issuer-chain certificates in the response.", Schema: querySchema},
					{Name: "private", In: openapi.ParameterInQuery, Description: "Include the decrypted private key bytes for leaf certificates.", Schema: querySchema},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Requested certificate bundle.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CertBundle]()}}},
					"400": {Description: "Invalid certificate name or query parameters."},
					"404": {Description: "Certificate not found."},
					"409": {Description: "Certificate is disabled."},
				},
			},
			Post: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Create certificate from CA name",
				Description: "Creates a new leaf certificate signed by the latest certificate authority version with the supplied name.",
				Parameters:  []openapi.Parameter{{Name: "name", In: openapi.ParameterInPath, Description: "Certificate authority name.", Required: true, Schema: nameSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Leaf certificate fields for the new certificate.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CreateCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created certificate.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate authority name or request body."},
					"404": {Description: "Signing certificate authority was not found."},
					"409": {Description: "Certificate already exists or signing certificate authority state prevents issuance."},
					"503": {Description: "Certificate issuance is not available because server certificate prerequisites are not configured."},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Update latest certificate",
				Description: "Updates mutable certificate metadata on the latest certificate version with the supplied name.",
				Parameters:  []openapi.Parameter{{Name: "name", In: openapi.ParameterInPath, Description: "Certificate name.", Required: true, Schema: nameSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Certificate metadata fields to update.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CertMeta]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated certificate.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate name or request body."},
					"404": {Description: "Certificate not found."},
				},
			},
		}
}

// CertByCAKeyHandler returns an http.HandlerFunc for creating a certificate signed by an explicit CA version.
func CertByCAKeyHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	nameSchema := jsonschema.MustFor[string]()
	serialSchema := jsonschema.MustFor[string]()
	querySchema := jsonschema.MustFor[bool]()

	return "cert/{name}/{serial}", func(w http.ResponseWriter, r *http.Request) {
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
			case http.MethodGet:
				_ = getCertByKey(r.Context(), manager, w, r, schema.CertKey{Name: name, Serial: serial})
			case http.MethodPatch:
				_ = updateCertByKey(r.Context(), manager, w, r, schema.CertKey{Name: name, Serial: serial})
			case http.MethodPost:
				_ = createCert(r.Context(), manager, w, r, schema.CertKey{Name: name, Serial: serial})
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate operations by version",
			Description: "Fetches a specific certificate version or creates a leaf certificate signed by a specific certificate authority version.",
			Get: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Get certificate by version",
				Description: "Returns the requested certificate version. Use query parameters to include issuer-chain certificates and the decrypted private key where available.",
				Parameters: []openapi.Parameter{
					{Name: "name", In: openapi.ParameterInPath, Description: "Certificate name.", Required: true, Schema: nameSchema},
					{Name: "serial", In: openapi.ParameterInPath, Description: "Certificate serial number.", Required: true, Schema: serialSchema},
					{Name: "chain", In: openapi.ParameterInQuery, Description: "Include issuer-chain certificates in the response.", Schema: querySchema},
					{Name: "private", In: openapi.ParameterInQuery, Description: "Include the decrypted private key bytes for leaf certificates.", Schema: querySchema},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Requested certificate bundle.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CertBundle]()}}},
					"400": {Description: "Invalid certificate key or query parameters."},
					"404": {Description: "Certificate not found."},
					"409": {Description: "Certificate is disabled."},
				},
			},
			Post: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Create certificate from CA version",
				Description: "Creates a new leaf certificate signed by the supplied certificate authority name and serial number.",
				Parameters: []openapi.Parameter{
					{Name: "name", In: openapi.ParameterInPath, Description: "Certificate authority name.", Required: true, Schema: nameSchema},
					{Name: "serial", In: openapi.ParameterInPath, Description: "Certificate authority serial number.", Required: true, Schema: serialSchema},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Leaf certificate fields for the new certificate.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CreateCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Created certificate.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate authority key or request body."},
					"404": {Description: "Signing certificate authority was not found."},
					"409": {Description: "Certificate already exists or signing certificate authority state prevents issuance."},
					"503": {Description: "Certificate issuance is not available because server certificate prerequisites are not configured."},
				},
			},
			Patch: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Update certificate by version",
				Description: "Updates mutable certificate metadata on the requested certificate version.",
				Parameters: []openapi.Parameter{
					{Name: "name", In: openapi.ParameterInPath, Description: "Certificate name.", Required: true, Schema: nameSchema},
					{Name: "serial", In: openapi.ParameterInPath, Description: "Certificate serial number.", Required: true, Schema: serialSchema},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Certificate metadata fields to update.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.CertMeta]()}},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Updated certificate.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate key or request body."},
					"404": {Description: "Certificate not found."},
				},
			},
		}
}

// CertRenewByNameHandler returns an http.HandlerFunc for renewing the latest certificate version with the provided name.
func CertRenewByNameHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	nameSchema := jsonschema.MustFor[string]()

	return "cert/{name}/renew", func(w http.ResponseWriter, r *http.Request) {
			name := r.PathValue("name")
			if name == "" {
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "name is required")
				return
			}

			switch r.Method {
			case http.MethodPost:
				_ = renewCertByName(r.Context(), manager, w, r, name)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate renewal by name",
			Description: "Renews the latest certificate version with the supplied name.",
			Post: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Renew latest certificate",
				Description: "Creates a new certificate version from the latest certificate with the supplied name and disables the previous version.",
				Parameters:  []openapi.Parameter{{Name: "name", In: openapi.ParameterInPath, Description: "Certificate name.", Required: true, Schema: nameSchema}},
				RequestBody: &openapi.RequestBody{
					Description: "Certificate renewal fields for the new certificate version.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.RenewCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Renewed certificate.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate name or request body."},
					"404": {Description: "Certificate not found."},
					"409": {Description: "Certificate or signer state prevents renewal."},
					"503": {Description: "Certificate renewal is not available because server certificate prerequisites are not configured."},
				},
			},
		}
}

// CertRenewByKeyHandler returns an http.HandlerFunc for renewing an explicit certificate version.
func CertRenewByKeyHandler(manager *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	nameSchema := jsonschema.MustFor[string]()
	serialSchema := jsonschema.MustFor[string]()

	return "cert/{name}/{serial}/renew", func(w http.ResponseWriter, r *http.Request) {
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
				_ = renewCertByKey(r.Context(), manager, w, r, schema.CertKey{Name: name, Serial: serial})
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Certificate renewal by version",
			Description: "Renews the specified certificate version.",
			Post: &openapi.Operation{
				Tags:        []string{"Certificate"},
				Summary:     "Renew certificate by version",
				Description: "Creates a new certificate version from the requested certificate name and serial number and disables the previous version.",
				Parameters: []openapi.Parameter{
					{Name: "name", In: openapi.ParameterInPath, Description: "Certificate name.", Required: true, Schema: nameSchema},
					{Name: "serial", In: openapi.ParameterInPath, Description: "Certificate serial number.", Required: true, Schema: serialSchema},
				},
				RequestBody: &openapi.RequestBody{
					Description: "Certificate renewal fields for the new certificate version.",
					Required:    true,
					Content:     map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.RenewCertRequest]()}},
				},
				Responses: map[string]openapi.Response{
					"201": {Description: "Renewed certificate.", Content: map[string]openapi.MediaType{"application/json": {Schema: jsonschema.MustFor[schema.Cert]()}}},
					"400": {Description: "Invalid certificate key or request body."},
					"404": {Description: "Certificate not found."},
					"409": {Description: "Certificate or signer state prevents renewal."},
					"503": {Description: "Certificate renewal is not available because server certificate prerequisites are not configured."},
				},
			},
		}
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
