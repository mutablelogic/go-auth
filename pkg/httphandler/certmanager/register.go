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

package certmanager

import (
	_ "embed"
	"errors"

	// Packages
	managerpkg "github.com/djthorpe/go-auth/pkg/certmanager"
	shared "github.com/djthorpe/go-auth/pkg/httphandler/internal"
	"github.com/djthorpe/go-auth/pkg/markdown"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Register interface {
	RegisterPath(path string, params *jsonschema.Schema, pathitem httprequest.PathItem) error
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed README.md
var doc string

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterCertManagerHandlers registers certmanager resource handlers with the provided router.
func RegisterCertManagerHandlers(manager *managerpkg.Manager, router server.HTTPRouter, authEnabled bool) error {
	// Get the router as a Register interface
	_ = authEnabled
	r := router.(Register)
	// TODO: Wrap path items with authentication and authorization if authEnabled is true

	doc := markdown.Parse(doc)

	// Add Group Header and Certificate Management description
	router.Spec().AddTag("Certificate Authority", doc.Section(2, "Certificate Authority").Body)
	router.Spec().AddTag("Certificate", doc.Section(2, "Certificates").Body)
	router.Spec().AddTagGroup("Certificate Management", "Certificate Authority", "Certificate")
	router.Spec().Info.Description = doc.Section(1, "Certificate Manager").Body

	// Register the handlers, and return any errors
	return errors.Join(
		r.RegisterPath(CAHandler(manager, doc)),
		r.RegisterPath(CAByNameRenewHandler(manager, doc)),
		r.RegisterPath(CAByKeyRenewHandler(manager, doc)),
		r.RegisterPath(CertHandler(manager, doc)),
		r.RegisterPath(CertByCAHandler(manager, doc)),
		r.RegisterPath(CertByCAKeyHandler(manager, doc)),
		r.RegisterPath(CertRenewByNameHandler(manager, doc)),
		r.RegisterPath(CertRenewByKeyHandler(manager, doc)),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// Translate internal errors to HTTP errors
func httpErr(err error) error {
	switch {
	case errors.Is(err, pg.ErrNotFound):
		return httpresponse.ErrNotFound.With(err)
	case errors.Is(err, pg.ErrConflict):
		return httpresponse.ErrConflict.With(err)
	case errors.Is(err, pg.ErrBadParameter):
		return httpresponse.ErrBadRequest.With(err)
	default:
		return shared.HTTPError(err)
	}
}
