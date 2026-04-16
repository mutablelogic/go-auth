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
	"net/http"

	// Packages
	manager "github.com/mutablelogic/go-auth/pkg/authmanager"
	middleware "github.com/mutablelogic/go-auth/pkg/middleware"
	oidc "github.com/mutablelogic/go-auth/pkg/oidc"
	schema "github.com/mutablelogic/go-auth/schema/auth"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func UserInfoHandler(manager *manager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return oidc.UserInfoPath, func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = getUserInfo(w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, &openapi.PathItem{Summary: "Authenticated user info", Description: "Returns the client-facing identity claims for the authenticated local token."}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func getUserInfo(w http.ResponseWriter, r *http.Request) error {
	user := middleware.UserFromContext(r.Context())
	if user == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError).With("authenticated user missing from context"))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), schema.NewUserInfo(user))
}
