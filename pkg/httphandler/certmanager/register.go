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
	"errors"
	"net/http"

	// Packages
	managerpkg "github.com/djthorpe/go-auth/pkg/certmanager"
	server "github.com/mutablelogic/go-server"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Register interface {
	RegisterFunc(path string, handler http.HandlerFunc, middleware bool, spec *openapi.PathItem) error
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterCertManagerHandlers registers certmanager resource handlers with the provided router.
func RegisterCertManagerHandlers(manager *managerpkg.Manager, router server.HTTPRouter, authEnabled bool) error {
	var result error
	_ = authEnabled
	register := func(path string, handler http.HandlerFunc, spec *openapi.PathItem) {
		result = errors.Join(result, router.(Register).RegisterFunc(path, handler, true, spec))
	}

	register(CAHandler(manager))
	register(CAByNameRenewHandler(manager))
	register(CAByKeyRenewHandler(manager))
	register(CertHandler(manager))
	register(CertByCAHandler(manager))
	register(CertByCAKeyHandler(manager))
	register(CertRenewByNameHandler(manager))
	register(CertRenewByKeyHandler(manager))

	return result
}
