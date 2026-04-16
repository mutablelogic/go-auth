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
	"fmt"
	"time"

	// Packages
	providerpkg "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
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
	privateKey   *rsa.PrivateKey
	schema       string
	channel      string
	sessionttl   time.Duration
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
	o.schema = schema.DefaultSchema
	o.sessionttl = schema.DefaultSessionTTL
	o.cleanupint = DefaultCleanupInterval
	o.cleanuplimit = DefaultCleanupLimit
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithPrivateKey stores the RSA private key for later token-signing use.
func WithPrivateKey(key *rsa.PrivateKey) Opt {
	return func(o *opt) error {
		if key == nil {
			return fmt.Errorf("private key is required")
		}
		o.privateKey = key
		return nil
	}
}

func WithProvider(provider providerpkg.Provider) Opt {
	return func(o *opt) error {
		if provider == nil {
			return fmt.Errorf("provider is required")
		}
		if o.providers == nil {
			o.providers = make(map[string]providerpkg.Provider)
		} else if _, exists := o.providers[provider.Key()]; exists {
			return fmt.Errorf("provider key %q already configured", provider.Key())
		}
		o.providers[provider.Key()] = provider
		return nil
	}
}

// WithSchema sets the database schema name to use for all queries. If not set the default schema is used.
func WithSchema(name string) Opt {
	return func(o *opt) error {
		if name == "" {
			return fmt.Errorf("schema name cannot be empty")
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
			return fmt.Errorf("notification channel cannot be empty")
		}
		o.channel = name
		return nil
	}
}

// WithNotifyChannel is kept as a compatibility alias.
func WithNotifyChannel(name string) Opt {
	return WithNotificationChannel(name)
}

// WithSessionTTL sets the session time-to-live duration.
func WithSessionTTL(ttl time.Duration) Opt {
	return func(o *opt) error {
		if ttl <= 0 {
			return fmt.Errorf("session TTL must be positive")
		}
		o.sessionttl = ttl
		return nil
	}
}

// WithCleanup sets how often Manager.Run prunes stale sessions and the
// maximum number of stale sessions deleted in a single cleanup pass.
func WithCleanup(interval time.Duration, limit int) Opt {
	return func(o *opt) error {
		if interval < 0 {
			return fmt.Errorf("cleanup interval must not be negative")
		}
		if limit < 0 {
			return fmt.Errorf("cleanup limit must not be negative")
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
			return fmt.Errorf("hooks are required")
		}
		o.hooks = hooks
		return nil
	}
}

// WithTracer sets the OpenTelemetry tracer used for manager spans.
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		if tracer == nil {
			return fmt.Errorf("tracer is required")
		}
		o.tracer = tracer
		return nil
	}
}
