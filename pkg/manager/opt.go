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

type opt struct {
	privateKey   *rsa.PrivateKey
	schema       string
	sessionttl   time.Duration
	cleanupint   time.Duration
	cleanuplimit int
	oauth        oidc.ClientConfigurations
	userhook     func(context.Context, schema.IdentityInsert, schema.UserMeta) (schema.UserMeta, error)
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
		if interval <= 0 {
			return fmt.Errorf("cleanup interval must be positive")
		}
		if limit <= 0 {
			return fmt.Errorf("cleanup limit must be positive")
		}
		o.cleanupint = interval
		o.cleanuplimit = limit
		return nil
	}
}

// WithUserHook sets a callback which can modify or reject a newly created
// user's metadata before it is inserted on first login.
func WithUserHook(fn func(context.Context, schema.IdentityInsert, schema.UserMeta) (schema.UserMeta, error)) Opt {
	return func(o *opt) error {
		if fn == nil {
			return fmt.Errorf("user hook is required")
		}
		o.userhook = fn
		return nil
	}
}
