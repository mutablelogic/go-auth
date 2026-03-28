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
	"strings"

	// Packages
	manager "github.com/djthorpe/go-auth/pkg/authmanager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema/auth"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func RevokeHandler(mgr *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.AuthRevokePath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodPost:
			_ = revokeToken(r.Context(), mgr, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Session revocation", Description: "Revoke a previously issued local session token so the underlying session can no longer be refreshed or accepted by session-aware checks."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func revokeToken(ctx context.Context, mgr *manager.Manager, w http.ResponseWriter, r *http.Request) error {
	token := ""
	if isFormEncodedTokenRequest(r) {
		if err := r.ParseForm(); err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		token = strings.TrimSpace(r.PostForm.Get("token"))
	} else {
		var req schema.RefreshRequest
		if err := httprequest.Read(r, &req); err != nil {
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
		}
		token = strings.TrimSpace(req.Token)
	}
	if token == "" {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With("token is required"))
	} else if config, err := mgr.OIDCConfig(r); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With(err))
	} else if claims, err := mgr.OIDCVerify(token, config.Issuer); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if session, err := sessionIDFromClaims(claims); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest).With(err))
	} else if _, err := mgr.RevokeSession(ctx, session); err != nil {
		return httpresponse.Error(w, httpErr(err))
	} else {
		w.WriteHeader(http.StatusNoContent)
		return nil
	}
}
