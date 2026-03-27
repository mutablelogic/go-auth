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

package manager

import (
	"context"
	"net/http"

	// Packages
	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ObjectHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "object", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			_ = listObjects(r.Context(), manager, w, r)
		default:
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
		}
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listObjects(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	objects, err := manager.List(ctx, schema.ObjectListRequest{})
	if err != nil {
		return httpresponse.Error(w, err)
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), objects)
}
