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

package handler

import (
	"context"
	"net/http"

	// Packages
	server "github.com/mutablelogic/go-server"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	ldap "github.com/mutablelogic/go-server/pkg/ldap"
	schema "github.com/mutablelogic/go-server/pkg/ldap/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func Register(ctx context.Context, router server.HTTPRouter, manager *ldap.Manager) {
	registerObject(ctx, router, schema.APIPrefix, manager)
}

func registerObject(ctx context.Context, router server.HTTPRouter, prefix string, manager *ldap.Manager) {
	router.HandleFunc(ctx, types.JoinPath(prefix, "object"), func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		httpresponse.Cors(w, r, router.Origin(), http.MethodGet, http.MethodPost)

		switch r.Method {
		case http.MethodOptions:
			_ = httpresponse.Empty(w, http.StatusOK)
		case http.MethodGet:
			_ = objectList(w, r, manager)
		case http.MethodPost:
			_ = objectCreate(w, r, manager)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	})

	router.HandleFunc(ctx, types.JoinPath(prefix, "object/{dn...}"), func(w http.ResponseWriter, r *http.Request) {
		defer r.Body.Close()
		httpresponse.Cors(w, r, router.Origin(), http.MethodGet, http.MethodDelete)

		switch r.Method {
		case http.MethodOptions:
			_ = httpresponse.Empty(w, http.StatusOK)
		case http.MethodGet:
			_ = objectGet(w, r, manager, r.PathValue("dn"))
		case http.MethodDelete:
			_ = objectDelete(w, r, manager, r.PathValue("dn"))
		case http.MethodPatch:
			_ = objectUpdate(w, r, manager, r.PathValue("dn"))
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	})
}
