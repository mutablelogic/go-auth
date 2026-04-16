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
	managerpkg "github.com/mutablelogic/go-auth/auth/manager"
	oidc "github.com/mutablelogic/go-auth/auth/oidc"
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func AuthCodeHandler(mgr *managerpkg.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.AuthCodePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = exchangeCode(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authorization code exchange", Description: "Exchanges a registered-provider authorization code and returns a signed local token plus userinfo."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func exchangeCode(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	if isFormEncodedTokenRequest(r) {
		return exchangeTokenFormRequest(ctx, mgr, w, r)
	}
	var req schema.AuthorizationCodeRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if err := req.Validate(); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else {
		provider, err := mgr.Provider(req.Provider)
		if err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		identity, err := provider.ExchangeAuthorizationCode(ctx, providerpkg.ExchangeRequest{
			Code:         req.Code,
			RedirectURL:  req.RedirectURL,
			CodeVerifier: req.CodeVerifier,
			Nonce:        req.Nonce,
		})
		if err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		if identity == nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).Withf("provider %q returned no identity", req.Provider))
		}
		return issueIdentityLoginResponse(ctx, mgr, w, r, *identity, req.Meta)
	}
}
