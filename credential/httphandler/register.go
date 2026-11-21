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
	schema "github.com/mutablelogic/go-server/broadcaster/schema"
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

	// Table is the table of the changes which are published, which a web UI
	// follows
	Table = "credential"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterProviderHandlers registers the handlers for a credential
// provider: storing a credential, and, when the provider encrypts with its
// own passphrases, getting a value with its passphrase. Values are never
// returned without the passphrase. When auth is true, the handlers need the
// credential scopes.
func RegisterProviderHandlers(provider credential.CredentialProvider, auth bool, with ...Opt) func(*httprouter.Router) error {
	return register(provider, nil, auth, with)
}

// RegisterManagerHandlers registers the handlers for a credential manager:
// the provider's handlers, and listing, getting the metadata of, deleting
// and, when the manager encrypts with its own passphrases, rotating
// credentials. Register the provider's or the manager's handlers, not both.
// When auth is true, the handlers need the credential scopes.
func RegisterManagerHandlers(manager credential.CredentialManager, auth bool, with ...Opt) func(*httprouter.Router) error {
	return register(manager, manager, auth, with)
}

// Opt is an option of the handlers
type Opt func(*options)

type options struct {
	publisher  Publisher
	signIns    []signIn
	webSignIns []webSignIn
}

// Publisher publishes changes, such as go-server's broadcaster, which a web
// UI follows
type Publisher interface {
	Publish(schema.Change) int
}

// WithPublisher publishes a change of a credential, by its key, without its
// value, after it's stored, described, rotated or deleted, so a web UI which
// follows the changes loads the credentials again
func WithPublisher(publisher Publisher) Opt {
	return func(o *options) {
		o.publisher = publisher
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func register(provider credential.CredentialProvider, manager credential.CredentialManager, auth bool, with []Opt) func(*httprouter.Router) error {
	var o options
	for _, opt := range with {
		opt(&o)
	}

	// Each server's web client, of its prefix, whose key is never a sign-in
	for i := range o.signIns {
		for j := range o.webSignIns {
			if o.webSignIns[j].prefix == o.signIns[i].prefix {
				o.signIns[i].web = &o.webSignIns[j]
			}
		}
	}
	notify := func(action schema.ChangeAction, key string) {
		if o.publisher != nil {
			o.publisher.Publish(schema.Change{Action: action, Table: Table, Row: key})
		}
	}
	return func(router *httprouter.Router) error {
		doc := opts.ParseMarkdown(HandlerDoc)
		router.Spec().AddTagGroup("Credentials", tag)
		router.Spec().AddTag(tag, doc.Section(2, "Credentials").Body)

		// Register the paths which have operations for the provider or
		// manager
		return errors.Join(
			registerCredential(router, provider, manager, auth, doc, notify),
			registerKey(router, provider, manager, auth, doc, notify),
			registerRotate(router, manager, auth, doc, notify),
			registerSignIn(router, provider, o.signIns, auth, doc, notify),
			registerWebSignIn(router, provider, o.signIns, auth, doc, notify),
		)
	}
}
