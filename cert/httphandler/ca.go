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
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// nameParams is the path parameter of a certificate's latest version
type nameParams struct {
	Name string `json:"name" help:"Certificate name"`
}

// keyParams are the path parameters of a certificate's version
type keyParams struct {
	Name   string `json:"name" help:"Certificate name"`
	Serial string `json:"serial" help:"Certificate serial number"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - PATHS

// registerCA registers creating certificate authorities, and renewing them
// by name or version
func registerCA(router *httprouter.Router, mgr *manager.Manager, auth bool, doc *opts.MarkdownDoc) error {
	return errors.Join(
		router.Register("ca", nil, func(path httprequest.PathItem) {
			path.Tag(tagCA)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				createCA(mgr, w, r)
			}, func(op httprequest.PathOperation) {
				op.Summary("Create a certificate authority")
				op.Description(doc.Section(3, "POST /ca").Body)
				op.RequestBody(jsonschema.MustFor[cert.CreateCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The certificate authority")
				op.ErrorResponse(http.StatusBadRequest, "Invalid request body or certificate authority parameters")
				op.ErrorResponse(http.StatusConflict, "The certificate authority exists, or the root certificate prevents issuance")
				op.ErrorResponse(http.StatusServiceUnavailable, "No root certificate or storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
		router.Register("ca/{name}/renew", jsonschema.MustFor[nameParams](), func(path httprequest.PathItem) {
			path.Tag(tagCA)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				renewCA(mgr, w, r, false)
			}, func(op httprequest.PathOperation) {
				op.Summary("Renew a certificate authority")
				op.Description(doc.Section(3, "POST /ca/{name}/renew").Body)
				op.RequestBody(jsonschema.MustFor[cert.RenewCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The new version of the certificate authority")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name or request body")
				op.ErrorResponse(http.StatusNotFound, "Certificate authority not found")
				op.ErrorResponse(http.StatusConflict, "The certificate authority or the root prevents renewal")
				op.ErrorResponse(http.StatusServiceUnavailable, "No storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
		router.Register("ca/{name}/{serial}/renew", jsonschema.MustFor[keyParams](), func(path httprequest.PathItem) {
			path.Tag(tagCA)
			path.Post(func(w http.ResponseWriter, r *http.Request) {
				renewCA(mgr, w, r, true)
			}, func(op httprequest.PathOperation) {
				op.Summary("Renew a version of a certificate authority")
				op.Description(doc.Section(3, "POST /ca/{name}/{serial}/renew").Body)
				op.RequestBody(jsonschema.MustFor[cert.RenewCertRequest]())
				op.JSONResponse(http.StatusCreated, jsonschema.MustFor[cert.Certificate](), "The new version of the certificate authority")
				op.ErrorResponse(http.StatusBadRequest, "Invalid name, serial or request body")
				op.ErrorResponse(http.StatusNotFound, "Certificate authority not found")
				op.ErrorResponse(http.StatusConflict, "The certificate authority or the root prevents renewal")
				op.ErrorResponse(http.StatusServiceUnavailable, "No storage passphrase is configured")
				security(op, auth, cert.ScopeCertWrite)
			})
		}),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HANDLERS

func createCA(mgr *manager.Manager, w http.ResponseWriter, r *http.Request) {
	var req cert.CreateCertRequest
	if err := httprequest.Read(r, &req); err != nil {
		httpresponse.Error(w, httpresponse.ErrBadRequest.Withf("%v", err))
		return
	}
	ca, err := mgr.CreateCA(r.Context(), req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), ca)
}

// renewCA renews the version of a certificate authority in the path, or its
// latest version when byKey is false
func renewCA(mgr *manager.Manager, w http.ResponseWriter, r *http.Request, byKey bool) {
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
	renewed, err := mgr.RenewCA(r.Context(), key, req)
	if err != nil {
		httpresponse.Error(w, httpErr(err))
		return
	}
	httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), renewed)
}

// pathKey is the certificate version in the path, or the latest version of
// the certificate named in the path when byKey is false
func pathKey(mgr *manager.Manager, r *http.Request, byKey bool) (cert.CertKey, error) {
	if byKey {
		return cert.CertKey{Name: r.PathValue("name"), Serial: r.PathValue("serial")}, nil
	}
	latest, err := mgr.GetLatestCert(r.Context(), r.PathValue("name"))
	if err != nil {
		return cert.CertKey{}, err
	}
	return latest.CertKey, nil
}
