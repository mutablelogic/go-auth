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

package auth

import (
	"context"
	"net/http"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ConfigHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.ConfigPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getOIDCConfig(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "OpenID discovery document", Description: "Returns the OpenID Connect configuration for this server."}
}

func JWKSHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.JWKSPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getJWKS(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "JSON Web Key Set", Description: "Returns the public signing keys for this server."}
}

func ProtectedResourceHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.ProtectedResourcePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getProtectedResourceMetadata(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "OAuth protected resource metadata", Description: "Returns OAuth protected-resource metadata for this server."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func getOIDCConfig(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.OIDCConfig(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}

func getProtectedResourceMetadata(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	config, err := mgr.ProtectedResourceMetadata(r)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), config)
}

func getJWKS(_ context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	jwks, err := mgr.OIDCJWKSet()
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), jwks)
}
