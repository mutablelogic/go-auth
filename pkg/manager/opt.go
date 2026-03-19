package manager

import (
	"crypto/rsa"
	"fmt"
	"time"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Opt configures a Manager during construction.
type Opt func(*opt) error

type opt struct {
	issuer     string
	privateKey *rsa.PrivateKey
	schema     string
	sessionttl time.Duration
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
