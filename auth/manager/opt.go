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
	"crypto/rsa"
	"strings"
	"time"

	// Packages
	"github.com/mutablelogic/go-auth"
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	"github.com/mutablelogic/go-server/pkg/types"
	trace "go.opentelemetry.io/otel/trace"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt configures a Manager during construction.
type Opt func(*opt) error

// UserCreationHook can modify or reject the proposed local user metadata
// before a new user is created on first login.
type UserCreationHook interface {
	OnUserCreate(context.Context, schema.IdentityInsert, schema.UserMeta) (schema.UserMeta, error)
}

// IdentityLinkHook decides whether a new provider identity may be linked to an
// existing local user.
type IdentityLinkHook interface {
	OnIdentityLink(context.Context, schema.IdentityInsert, *schema.User) error
}

const (
	DefaultCleanupInterval = time.Hour
	DefaultCleanupLimit    = 100
)

// opt combines all configuration options for Manager.
type opt struct {
	signer       string
	keys         map[string]*rsa.PrivateKey
	issuer       string
	schema       string
	channel      string
	sessionttl   time.Duration
	refreshttl   time.Duration
	cleanupint   time.Duration
	cleanuplimit int
	providers    map[string]providerpkg.Provider
	hooks        any
	tracer       trace.Tracer
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func (o *opt) apply(opts ...Opt) error {
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		if err := opt(o); err != nil {
			return err
		}
	}
	return nil
}

func (o *opt) defaults() {
	o.keys = make(map[string]*rsa.PrivateKey)
	o.schema = schema.DefaultSchema
	o.sessionttl = schema.DefaultSessionTTL
	o.refreshttl = schema.DefaultRefreshTTL
	o.cleanupint = DefaultCleanupInterval
	o.cleanuplimit = DefaultCleanupLimit
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithSigner stores the RSA private key for later token-signing use.
// The supplied key ID is used in the "kid" header of signed tokens and must be unique among all configured keys.
// The last configured key becomes the default signing key used for new tokens and JWKS responses.
func WithSigner(kid string, key *rsa.PrivateKey) Opt {
	return func(o *opt) error {
		if key == nil {
			return auth.ErrBadParameter.With("private key is required")
		}
		if !types.IsIdentifier(kid) {
			return auth.ErrBadParameter.Withf("Invalid Key ID %q", kid)
		} else if _, exists := o.keys[kid]; exists {
			return auth.ErrBadParameter.Withf("Key ID %q already configured", kid)
		} else {
			o.keys[kid] = key
			o.signer = kid
		}
		return nil
	}
}

// WithIssuer stores the canonical issuer used for this server's OIDC metadata
// and locally-signed token verification.
func WithIssuer(issuer string) Opt {
	return func(o *opt) error {
		issuer = strings.TrimSpace(issuer)
		if issuer == "" {
			return auth.ErrBadParameter.With("issuer is required")
		}
		o.issuer = issuer
		return nil
	}
}

func WithProvider(provider providerpkg.Provider) Opt {
	return func(o *opt) error {
		if provider == nil {
			return auth.ErrBadParameter.With("provider is required")
		}
		if o.providers == nil {
			o.providers = make(map[string]providerpkg.Provider)
		} else if _, exists := o.providers[provider.Key()]; exists {
			return auth.ErrBadParameter.Withf("provider key %q already configured", provider.Key())
		}
		o.providers[provider.Key()] = provider
		return nil
	}
}

// WithSchema sets the database schema name to use for all queries. If not set the default schema is used.
func WithSchema(name string) Opt {
	return func(o *opt) error {
		if name == "" {
			return auth.ErrBadParameter.With("schema name cannot be empty")
		}
		o.schema = name
		return nil
	}
}

// WithNotificationChannel sets the PostgreSQL LISTEN/NOTIFY channel used by the
// table change triggers created during bootstrap.
func WithNotificationChannel(name string) Opt {
	return func(o *opt) error {
		if name == "" {
			return auth.ErrBadParameter.With("notification channel cannot be empty")
		}
		o.channel = name
		return nil
	}
}

// WithTTL sets the session and refresh token time-to-live durations.
func WithTTL(sessionTTL, refreshTTL time.Duration) Opt {
	return func(o *opt) error {
		if sessionTTL <= 0 {
			return auth.ErrBadParameter.With("session TTL must be positive")
		} else if refreshTTL <= 0 {
			return auth.ErrBadParameter.With("refresh TTL must be positive")
		} else if sessionTTL >= refreshTTL {
			return auth.ErrBadParameter.With("session TTL must be less than refresh TTL")
		}
		o.sessionttl = sessionTTL
		o.refreshttl = refreshTTL
		return nil
	}
}

// WithCleanup sets how often Manager.Run prunes stale sessions and the
// maximum number of stale sessions deleted in a single cleanup pass.
func WithCleanup(interval time.Duration, limit int) Opt {
	return func(o *opt) error {
		if interval < 0 {
			return auth.ErrBadParameter.With("cleanup interval must not be negative")
		}
		if limit < 0 {
			return auth.ErrBadParameter.With("cleanup limit must not be negative")
		}
		if interval == 0 {
			interval = DefaultCleanupInterval
		}
		if limit == 0 {
			limit = DefaultCleanupLimit
		}
		o.cleanupint = interval
		o.cleanuplimit = limit
		return nil
	}
}

// WithHooks sets a hook object that may implement one or more supported login
// hook interfaces such as UserCreationHook or IdentityLinkHook.
func WithHooks(hooks any) Opt {
	return func(o *opt) error {
		if hooks == nil {
			return auth.ErrBadParameter.With("hooks are required")
		}
		o.hooks = hooks
		return nil
	}
}

// WithTracer sets the OpenTelemetry tracer used for manager spans.
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		if tracer == nil {
			return auth.ErrBadParameter.With("tracer is required")
		}
		o.tracer = tracer
		return nil
	}
}
