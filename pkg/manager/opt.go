package manager

import (
	"context"
	"crypto/rsa"
	"fmt"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt configures a Manager during construction.
type Opt func(*opt) error

type opt struct {
	issuer       string
	privateKey   *rsa.PrivateKey
	schema       string
	sessionttl   time.Duration
	cleanupint   time.Duration
	cleanuplimit int
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

// WithIssuer sets the canonical issuer used for locally signed tokens.
func WithIssuer(issuer string) Opt {
	return func(o *opt) error {
		if issuer == "" {
			return fmt.Errorf("issuer cannot be empty")
		}
		o.issuer = issuer
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
