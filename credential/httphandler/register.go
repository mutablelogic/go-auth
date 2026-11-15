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
	credential "github.com/mutablelogic/go-auth/credential"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed README.md
var HandlerDoc []byte

const (
	// tag is the OpenAPI tag of the credential operations
	tag = "Credentials"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterProviderHandlers registers the handlers for a credential
// provider: storing a credential, and, when the provider encrypts with its
// own passphrases, getting a value with its passphrase. Values are never
// returned without the passphrase. When auth is true, the handlers need the
// credential scopes.
func RegisterProviderHandlers(provider credential.CredentialProvider, auth bool) func(*httprouter.Router) error {
	return register(provider, nil, auth)
}

// RegisterManagerHandlers registers the handlers for a credential manager:
// the provider's handlers, and listing, getting the metadata of, deleting
// and, when the manager encrypts with its own passphrases, rotating
// credentials. Register the provider's or the manager's handlers, not both.
// When auth is true, the handlers need the credential scopes.
func RegisterManagerHandlers(manager credential.CredentialManager, auth bool) func(*httprouter.Router) error {
	return register(manager, manager, auth)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func register(provider credential.CredentialProvider, manager credential.CredentialManager, auth bool) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		doc := opts.ParseMarkdown(HandlerDoc)
		router.Spec().AddTagGroup("Credentials", tag)
		router.Spec().AddTag(tag, doc.Section(2, "Credentials").Body)

		// Register the paths which have operations for the provider or
		// manager
		return errors.Join(
			registerCredential(router, provider, manager, auth, doc),
			registerKey(router, provider, manager, auth, doc),
			registerRotate(router, manager, auth, doc),
		)
	}
}
