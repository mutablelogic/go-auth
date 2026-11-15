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
	"errors"
	"net/http"

	// Packages
	cert "github.com/mutablelogic/go-auth/cert/cert"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// CertQuery is what's returned with a certificate
type CertQuery struct {
	Chain   bool `json:"chain,omitempty" help:"Include the issuer chain, up to the root"`
	Private bool `json:"private,omitempty" help:"Include the private key, of a leaf certificate"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerCert registers listing certificates, and getting, creating,
// updating and renewing them by name or version
func registerCert(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("cert", nil, func(path httprequest.PathItem) {
			path.Tag(tagCert)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				listCerts(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("List certificates")
				op.Description(doc.Section(3, "GET /cert").Body)
				op.Query(jsonschema.MustFor[cert.CertListRequest]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.CertList](), "Certificates, without their private keys")
				op.ErrorResponse(http.StatusBadRequest, "Invalid filter or pagination parameters")
				security(op, auth, cert.ScopeCertRead)
			})
		}),
		router.Register("cert/{name}", jsonschema.MustFor[nameParams](), func(path httprequest.PathItem) {
			path.Tag(tagCert)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				getCert(mgr, w, r, false)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get a certificate")
				op.Description(doc.Section(3, "GET /cert/{name}").Body)
				op.Query(jsonschema.MustFor[CertQuery]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.CertBundle](), "The latest version of the certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or query, or the private key of a certificate authority")
				op.ErrorResponse(http.StatusNotFound, "Certificate not found")
				op.ErrorResponse(http.StatusConflict, "The certificate is disabled")
				security(op, auth, cert.ScopeCertRead)
			})
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				createCert(mgr, w, r, false)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create a certificate")
				op.Description(doc.Section(3, "POST /cert/{name}").Body)
				op.RequestBody(jsonschema.MustFor[cert.CreateCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or request body")
				op.ErrorResponse(http.StatusNotFound, "Certificate authority not found")
				op.ErrorResponse(http.StatusConflict, "The certificate exists, or the certificate authority prevents issuance")
				op.ErrorResponse(http.StatusServiceUnavailable, "No storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
			path.Patch(func(w http.ResponseWriter, r *http.Request) {
				updateCert(mgr, w, r, false)
			}, func(op httprequest.PathOperation) {
				op.Summary("Update a certificate")
				op.Description(doc.Section(3, "PATCH /cert/{name}").Body)
				op.RequestBody(jsonschema.MustFor[cert.CertMeta]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.Certificate](), "The latest version of the certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or request body, or the root certificate")
				op.ErrorResponse(http.StatusNotFound, "Certificate not found")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
		router.Register("cert/{name}/{serial}", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
			path.Tag(tagCert)
			path.Get(func(w http.ResponseWriter, r *http.Request) {
				getCert(mgr, w, r, true)
			}, func(op httprequest.PathOperation) {
				op.Summary("Get a version of a certificate")
				op.Description(doc.Section(3, "GET /cert/{name}/{serial}").Body)
				op.Query(jsonschema.MustFor[CertQuery]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.CertBundle](), "The version of the certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name, serial or query, or the private key of a certificate authority")
				op.ErrorResponse(http.StatusNotFound, "Certificate not found")
				op.ErrorResponse(http.StatusConflict, "The certificate is disabled")
				security(op, auth, cert.ScopeCertRead)
			})
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				createCert(mgr, w, r, true)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create a certificate with a version of a certificate authority")
				op.Description(doc.Section(3, "POST /cert/{name}/{serial}").Body)
				op.RequestBody(jsonschema.MustFor[cert.CreateCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name, serial or request body")
				op.ErrorResponse(http.StatusNotFound, "Certificate authority not found")
				op.ErrorResponse(http.StatusConflict, "The certificate exists, or the certificate authority prevents issuance")
				op.ErrorResponse(http.StatusServiceUnavailable, "No storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
			path.Patch(func(w http.ResponseWriter, r *http.Request) {
				updateCert(mgr, w, r, true)
			}, func(op httprequest.PathOperation) {
				op.Summary("Update a version of a certificate")
				op.Description(doc.Section(3, "PATCH /cert/{name}/{serial}").Body)
				op.RequestBody(jsonschema.MustFor[cert.CertMeta]())
				op.JSONResponse(http.StatusOK, jsonschema.MustFor[cert.Certificate](), "The version of the certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name, serial or request body, or the root certificate")
				op.ErrorResponse(http.StatusNotFound, "Certificate not found")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
		router.Register("cert/{name}/renew", jsonschema.MustFor[nameParams](), func(path httprequest.PathItem) {
			path.Tag(tagCert)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				renewCert(mgr, w, r, false)
			}, func(op httprequest.PathOperation) {
				op.Summary("Renew a certificate")
				op.Description(doc.Section(3, "POST /cert/{name}/renew").Body)
				op.RequestBody(jsonschema.MustFor[cert.RenewCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The new version of the certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or request body")
				op.ErrorResponse(http.StatusNotFound, "Certificate not found")
				op.ErrorResponse(http.StatusConflict, "The certificate or its certificate authority prevents renewal")
				op.ErrorResponse(http.StatusServiceUnavailable, "No storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
		router.Register("cert/{name}/{serial}/renew", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
			path.Tag(tagCert)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				renewCert(mgr, w, r, true)
			}, func(op httprequest.PathOperation) {
				op.Summary("Renew a version of a certificate")
				op.Description(doc.Section(3, "POST /cert/{name}/{serial}/renew").Body)
				op.RequestBody(jsonschema.MustFor[cert.RenewCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The new version of the certificate")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name, serial or request body")
				op.ErrorResponse(http.StatusNotFound, "Certificate not found")
				op.ErrorResponse(http.StatusConflict, "The certificate or its certificate authority prevents renewal")
				op.ErrorResponse(http.StatusServiceUnavailable, "No storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

func listCerts(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	var req cert.CertListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	certs, err := mgr.ListCerts(r.Context(), req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), certs)
}

// getCert returns the version of a certificate in the path, or its latest
// version when byKey is false, with its chain or private key when they're
// asked for
func getCert(mgr *manager.Manager, w http.ResponseWriter, r *http.Request, byKey bool) {
	// A private key isn't cached
	var query CertQuery
	if err := httprequest.Query(r.URL.Query(), &query); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	} else if query.Private {
		w.Header().Set("Cache-Control", "no-store")
	}
	key, err := pathKey(mgr, r, byKey)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	bundle, err := certBundle(r.Context(), mgr, key, query)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), bundle)
}

// createCert creates a leaf certificate, signed by the version of the
// certificate authority in the path, or its latest version when byKey is
// false
func createCert(mgr *manager.Manager, w http.ResponseWriter, r *http.Request, byKey bool) {
	var req cert.CreateCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	ca, err := pathKey(mgr, r, byKey)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	created, err := mgr.CreateCert(r.Context(), req, ca)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), created)
}

// updateCert updates the metadata of the version of a certificate in the
// path, or its latest version when byKey is false
func updateCert(mgr *manager.Manager, w http.ResponseWriter, r *http.Request, byKey bool) {
	var req cert.CertMeta
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	key, err := pathKey(mgr, r, byKey)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	updated, err := mgr.UpdateCert(r.Context(), key, req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), updated)
}

// renewCert renews the version of a leaf certificate in the path, or its
// latest version when byKey is false
func renewCert(mgr *manager.Manager, w http.ResponseWriter, r *http.Request, byKey bool) {
	var req cert.RenewCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	key, err := pathKey(mgr, r, byKey)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	renewed, err := mgr.RenewCert(r.Context(), key, req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), renewed)
}

// certBundle is the certificate, with its issuer chain and private key when
// they're asked for. A disabled certificate is a conflict.
func certBundle(ctx context.Context, mgr *manager.Manager, key cert.CertKey, query CertQuery) (*cert.CertBundle, error) {
	bundle := new(cert.CertBundle)
	if query.Private {
		withKey, err := mgr.GetPrivateKey(ctx, key)
		if err != nil {
			return nil, err
		}
		bundle.Certificate = withKey.Certificate
		bundle.Key = withKey.Key
	} else if found, err := mgr.GetCert(ctx, key); err != nil {
		return nil, err
	} else {
		bundle.Certificate = *found
	}
	if !types.Value(bundle.Enabled) {
		return nil, httpresponse.ErrConflict.With("certificate is disabled")
	}
	if query.Chain {
		chain, err := mgr.GetCertChain(ctx, bundle.CertKey)
		if err != nil {
			return nil, err
		}
		// The chain starts with the certificate, which isn't repeated
		if len(chain) > 0 && chain[0].CertKey == bundle.CertKey {
			chain = chain[1:]
		}
		if len(chain) > 0 {
			bundle.Chain = chain
		}
	}
	return bundle, nil
}
