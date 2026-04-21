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

package middleware

import (
	"fmt"
	"net/http"

	// Packages
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type bearerAuth struct {
	authenticator Authenticator
}

var _ httprouter.SecurityScheme = (*bearerAuth)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewBearerAuth(authenticator Authenticator) *bearerAuth {
	return &bearerAuth{
		authenticator: authenticator,
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (b *bearerAuth) Spec() openapi.SecurityScheme {
	return openapi.SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
	}
}

func (b *bearerAuth) Wrap(handler http.HandlerFunc, scopes []string) http.HandlerFunc {
	wrapper := AuthN(b.authenticator)
	return wrapper(func(w http.ResponseWriter, r *http.Request) {
		if user := UserFromContext(r.Context()); user == nil {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusUnauthorized).With("invalid token: no user in context"))
			return
		} else if !user.HasAllScopes(scopes...) {
			_ = httpresponse.Error(w, httpresponse.Err(http.StatusForbidden).With("insufficient permissions"), fmt.Sprintf("Required scopes: %q", scopes))
			return
		}
		handler(w, r)
	})
}
