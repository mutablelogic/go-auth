package manager

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	// Packages
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
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
	oauth        oidc.ClientConfigurations
	hooks        any
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
	o.channel = ""
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

// WithOAuthClient stores the upstream OAuth client configuration. The client
// ID and issuer are exposed via /auth/config, while the client secret remains
// server-side.
func WithOAuthClient(key, issuer, clientID, clientSecret string) Opt {
	return func(o *opt) error {
		if key == "" {
			return fmt.Errorf("oauth key cannot be empty")
		}
		if issuer == "" {
			return fmt.Errorf("oauth issuer cannot be empty")
		}
		if o.oauth == nil {
			o.oauth = make(oidc.ClientConfigurations)
		} else if _, exists := o.oauth[key]; exists {
			return fmt.Errorf("oauth key %q already configured", key)
		}
		o.oauth[key] = oidc.ClientConfiguration{
			PublicClientConfiguration: oidc.PublicClientConfiguration{
				Issuer:   issuer,
				ClientID: clientID,
				Provider: schema.ProviderOAuth,
			},
			ClientSecret: clientSecret,
		}
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
