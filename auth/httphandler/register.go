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

// Package httphandler registers the HTTP handlers which sign people in with
// providers, such as Google, GitHub and LDAP, and exchange who they are for
// what the server makes of it
package httphandler

import (
	"context"
	"crypto/rand"
	_ "embed"
	"net/url"
	"strings"
	"time"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	store "github.com/mutablelogic/go-auth/auth/store"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ExchangeFunc is what's done with an identity, once someone has signed in,
// whose result is the response, or whose error refuses it
type ExchangeFunc func(ctx context.Context, identity *schema.Identity) (any, error)

// Opt is an option of the handlers
type Opt func(*options) error

type options struct {
	key      []byte
	base     *url.URL
	exchange ExchangeFunc
	response *jsonschema.Schema
	sessions store.SessionStore
	ttl      time.Duration
	now      func() time.Time

	// The OAuth server
	oauth     bool
	redirects []string
	signin    string
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

//go:embed README.md
var HandlerDoc []byte

const (
	// The OpenAPI tag of the operations
	tagSignIn = "Sign In"

	// The time a sign-in has to return from a provider
	defaultTTL = 10 * time.Minute
)

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithKey seals the state of sign-ins with the key, of 32 bytes, so they
// can be completed by another server with the key, or after a restart.
// Without it, the key is random.
func WithKey(key []byte) Opt {
	return func(o *options) error {
		if len(key) != 32 {
			return httpresponse.ErrBadRequest.With("The key of sign-ins is 32 bytes")
		}
		o.key = key
		return nil
	}
}

// WithBaseURL is the URL the server is reached at, such as
// https://auth.example.com, which providers redirect back to. Without it,
// it's the request's scheme and host.
func WithBaseURL(base string) Opt {
	return func(o *options) error {
		u, err := url.Parse(strings.TrimSuffix(base, "/"))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return httpresponse.ErrBadRequest.Withf("Invalid base URL %q", base)
		}
		o.base = u
		return nil
	}
}

// WithExchange does fn with an identity, once someone has signed in, and
// returns its result, whose schema is the response's, in the OpenAPI
// specification, such as a session's. Without it, the identity is returned.
func WithExchange(fn ExchangeFunc, response *jsonschema.Schema) Opt {
	return func(o *options) error {
		if fn == nil || response == nil {
			return httpresponse.ErrBadRequest.With("An exchange needs a function, and the schema of its result")
		}
		o.exchange, o.response = fn, response
		return nil
	}
}

// WithSessions sets a session's token as a cookie, when signing in is
// exchanged for a session, for a browser, and registers getting the
// session and signing out, which need the security scheme, which is
// registered first
func WithSessions(sessions store.SessionStore) Opt {
	return func(o *options) error {
		o.sessions = sessions
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// RegisterHandlers registers signing in with the providers, which need
// unique names: listing them, a redirect provider's sign-in and callback,
// and a password provider's sign-in
func RegisterHandlers(providers []provider.Provider, opt ...Opt) func(*httprouter.Router) error {
	return func(router *httprouter.Router) error {
		o := options{ttl: defaultTTL, now: time.Now, response: jsonschema.MustFor[schema.Identity](), exchange: func(_ context.Context, identity *schema.Identity) (any, error) {
			return identity, nil
		}}
		for _, fn := range opt {
			if err := fn(&o); err != nil {
				return err
			}
		}
		if o.key == nil {
			o.key = make([]byte, 32)
			if _, err := rand.Read(o.key); err != nil {
				return err
			}
		}
		s, err := newSealer(o.key)
		if err != nil {
			return err
		}

		// The providers, by name
		byName := make(map[string]provider.Provider, len(providers))
		for _, p := range providers {
			name := p.Meta().Name
			if _, exists := byName[name]; exists {
				return httpresponse.ErrConflict.Withf("There's more than one provider named %q", name)
			}
			byName[name] = p
		}

		doc := opts.ParseMarkdown(HandlerDoc)
		router.Spec().AddTag(tagSignIn, doc.Section(2, tagSignIn).Body)
		h := &handlers{providers: providers, byName: byName, sealer: s, options: o}
		if err := registerSignIn(router, h, doc); err != nil {
			return err
		} else if !o.oauth {
			return nil
		} else if o.sessions == nil {
			return httpresponse.ErrBadRequest.With("The OAuth server issues sessions, so it needs WithSessions")
		}
		router.Spec().AddTag(tagOAuth, doc.Section(2, tagOAuth).Body)
		return registerOAuth(router, h, doc)
	}
}

// Providers returns what the providers are, for anyone to see, such as on
// a sign-in page, or in the server's configuration
func Providers(providers []provider.Provider) []schema.ProviderMeta {
	result := make([]schema.ProviderMeta, 0, len(providers))
	for _, p := range providers {
		result = append(result, p.Meta())
	}
	return result
}
