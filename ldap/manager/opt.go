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
	"errors"
	"net/url"

	// Packages
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	trace "go.opentelemetry.io/otel/trace"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

type opt struct {
	url        *url.URL
	user       string
	pass       string
	dn         *schema.DN
	skipverify bool
	users      *schema.Group
	groups     *schema.Group
	tracer     trace.Tracer
}

// Opt represents a function that modifies the options
type Opt func(*opt) error

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func applyOpts(opts ...Opt) (*opt, error) {
	var o opt
	for _, fn := range opts {
		if err := fn(&o); err != nil {
			return nil, err
		}
	}
	return &o, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithUrl sets the directory's URL, ldap or ldaps, which can have the user
// and password
func WithUrl(v string) Opt {
	return func(o *opt) error {
		u, err := url.Parse(v)
		if err != nil {
			// A url.Error has the URL, with its password, so only its
			// cause is returned
			var urlErr *url.Error
			if errors.As(err, &urlErr) {
				err = urlErr.Err
			}
			return httpresponse.ErrBadRequest.Withf("url is invalid: %v", err)
		}
		o.url = u
		return nil
	}
}

// WithBaseDN sets the base DN, which the manager's DNs are under
func WithBaseDN(v string) Opt {
	return func(o *opt) error {
		if v == "" {
			return nil
		}
		dn, err := schema.NewDN(v)
		if err != nil {
			return httpresponse.ErrBadRequest.Withf("DN is invalid: %v", err)
		}
		o.dn = dn
		return nil
	}
}

// WithUserDN sets the DN of the users, and their object classes
func WithUserDN(dn string, classes ...string) Opt {
	return func(o *opt) error {
		if dn == "" {
			return httpresponse.ErrBadRequest.With("DN is empty")
		}
		bdn, err := schema.NewDN(dn)
		if err != nil {
			return httpresponse.ErrBadRequest.Withf("DN is invalid: %v", err)
		}
		o.users = types.Ptr(schema.Group{DN: bdn, ObjectClass: classes})
		return nil
	}
}

// WithGroupDN sets the DN of the groups
func WithGroupDN(dn string) Opt {
	return func(o *opt) error {
		if dn == "" {
			return httpresponse.ErrBadRequest.With("DN is empty")
		}
		bdn, err := schema.NewDN(dn)
		if err != nil {
			return httpresponse.ErrBadRequest.Withf("DN is invalid: %v", err)
		}
		o.groups = types.Ptr(schema.Group{DN: bdn})
		return nil
	}
}

// WithUser sets the user, rather than the URL's, which is a name under the
// base DN, or a DN
func WithUser(v string) Opt {
	return func(o *opt) error {
		if v != "" {
			o.user = v
		}
		return nil
	}
}

// WithPassword sets the password, rather than the URL's
func WithPassword(v string) Opt {
	return func(o *opt) error {
		if v != "" {
			o.pass = v
		}
		return nil
	}
}

// WithSkipVerify doesn't verify an ldaps server's certificate
func WithSkipVerify() Opt {
	return func(o *opt) error {
		o.skipverify = true
		return nil
	}
}

// WithTracer sets the OpenTelemetry tracer used for manager spans
func WithTracer(tracer trace.Tracer) Opt {
	return func(o *opt) error {
		o.tracer = tracer
		return nil
	}
}
