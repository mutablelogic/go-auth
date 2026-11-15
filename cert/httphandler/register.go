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
	_ "embed"
	"errors"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/cert/manager"
	pg "github.com/mutablelogic/go-pg"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed README.md
var HandlerDoc []byte

const (
	// The OpenAPI tags of the certificate authority and certificate
	// operations
	tagCA      = "Certificate Authorities"
	tagCert    = "Certificates"
	tagSubject = "Subjects"

	securityScheme = "bearerAuth"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterHandlers registers the handlers of the certificate manager:
// creating and renewing certificate authorities, listing, getting,
// creating, renewing and updating certificates, and managing the subjects
// they're created with. When auth is true, the
// handlers need the certificate scopes.
func RegisterHandlers(manager *manager.Manager, auth bool) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		doc := opts.ParseMarkdown(HandlerDoc)
		router.Spec().AddTag(tagCA, doc.Section(2, tagCA).Body)
		router.Spec().AddTag(tagCert, doc.Section(2, tagCert).Body)
		router.Spec().AddTag(tagSubject, doc.Section(2, tagSubject).Body)
		router.Spec().AddTagGroup("Certificate Management", tagCA, tagCert, tagSubject)

		return errors.Join(
			registerCA(router, manager, auth, doc),
			registerCert(router, manager, auth, doc),
			registerSubject(router, manager, auth, doc),
		)
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// security requires the bearer token scheme, with the scopes, when auth is
// true
func security(op httprequest.PathOperation, auth bool, scopes ...string) {
	if auth {
		op.Security(securityScheme, scopes...)
	}
}

// httpErr translates an error from the manager into an HTTP error: the
// manager's own are HTTP errors already, and the database's are mapped by
// go-pg
func httpErr(err error) error {
	var httpErr httpresponse.Err
	var authErr auth.Err
	switch {
	case errors.As(err, &httpErr):
		return err
	case errors.As(err, &authErr):
		return auth.HTTPError(err)
	default:
		return pg.HTTPError(err)
	}
}
