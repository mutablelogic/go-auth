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

package ldap

import (
	"net/url"

	// Packages
	"github.com/mutablelogic/go-server/pkg/httpresponse"
	schema "github.com/mutablelogic/go-server/pkg/ldap/schema"
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
}

// Opt represents a function that modifies the options
type Opt func(*opt) error

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func applyOpts(opts ...Opt) (*opt, error) {
	var o opt

	// Apply the options
	for _, fn := range opts {
		if err := fn(&o); err != nil {
			return nil, err
		}
	}

	// Return success
	return &o, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func WithUserSchema(dn string, classes ...string) Opt {
	return func(o *opt) error {
		if dn == "" {
			return httpresponse.ErrBadRequest.With("DN is empty")
		} else if bdn, err := schema.NewDN(dn); err != nil {
			return httpresponse.ErrBadRequest.With("DN is invalid: ", err)
		} else {
			o.users = &schema.Group{DN: bdn, ObjectClass: classes}
		}
		return nil
	}
}

func WithGroupSchema(dn string, classes ...string) Opt {
	return func(o *opt) error {
		if dn == "" {
			return httpresponse.ErrBadRequest.With("DN is empty")
		} else if bdn, err := schema.NewDN(dn); err != nil {
			return httpresponse.ErrBadRequest.With("DN is invalid: ", err)
		} else {
			o.groups = &schema.Group{DN: bdn, ObjectClass: classes}
		}
		return nil
	}
}

func WithUrl(v string) Opt {
	return func(o *opt) error {
		if u, err := url.Parse(v); err != nil {
			return err
		} else {
			o.url = u
		}
		return nil
	}
}

func WithBaseDN(v string) Opt {
	return func(o *opt) error {
		if v == "" {
			return nil
		} else if bdn, err := schema.NewDN(v); err != nil {
			return httpresponse.ErrBadRequest.With("DN is invalid: ", err)
		} else {
			o.dn = bdn
		}
		return nil
	}
}

func WithUser(v string) Opt {
	return func(o *opt) error {
		if v != "" {
			o.user = v
		}
		return nil
	}
}

func WithPassword(v string) Opt {
	return func(o *opt) error {
		if v != "" {
			o.pass = v
		}
		return nil
	}
}

func WithSkipVerify() Opt {
	return func(o *opt) error {
		o.skipverify = true
		return nil
	}
}
