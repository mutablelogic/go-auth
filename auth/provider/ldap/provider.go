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

// Package ldap is a provider of an LDAP directory, which is signed in with
// a username and password, which is checked with a bind as the user, whose
// groups are the identity's.
package ldap

import (
	"context"
	"errors"
	"fmt"
	"net/url"

	// Packages
	provider "github.com/mutablelogic/go-auth/auth/provider"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	ldapschema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// INTERFACES

// Manager is what the provider needs of an LDAP manager: a user, by name, a
// bind, which checks a password, the groups a user is in, and the
// directory's status, for the identity's issuer
type Manager interface {
	GetUser(ctx context.Context, name string) (*ldapschema.Object, error)
	Bind(ctx context.Context, dn, password string) (*ldapschema.Object, error)
	ListGroups(ctx context.Context, req ldapschema.GroupListRequest) (*ldapschema.ObjectList, error)
	Status() ldapschema.Status
}

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Provider is an LDAP directory, through its manager
type Provider struct {
	meta    schema.ProviderMeta
	manager Manager
}

// Opt is an option of a provider
type Opt func(*Provider) error

var _ provider.Provider = (*Provider)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns the directory of the manager, named ldap, which needs users
func New(manager Manager, opts ...Opt) (*Provider, error) {
	if manager == nil {
		return nil, httpresponse.ErrBadRequest.With("LDAP needs a manager")
	} else if manager.Status().UserDN == "" {
		return nil, httpresponse.ErrBadRequest.With("LDAP needs users, with a users' DN, to sign in with")
	}
	self := &Provider{
		meta:    schema.ProviderMeta{Name: "ldap", Label: "LDAP", Kind: schema.ProviderKindPassword},
		manager: manager,
	}
	for _, opt := range opts {
		if err := opt(self); err != nil {
			return nil, err
		}
	}
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// OPTIONS

// WithName names the provider, which is in its paths, and labels it, to
// show, such as for a directory's name
func WithName(name, label string) Opt {
	return func(p *Provider) error {
		if name == "" {
			return httpresponse.ErrBadRequest.With("A provider needs a name")
		}
		p.meta.Name, p.meta.Label = name, label
		if label == "" {
			p.meta.Label = name
		}
		return nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Meta describes the provider
func (p *Provider) Meta() schema.ProviderMeta {
	return p.meta
}

// Exchange checks the username's password, with a bind as the user, and
// returns its identity: by its DN, with its email address, name, and the
// groups it's in. A user who isn't found, and a password which isn't right,
// are the same error, so which isn't said.
func (p *Provider) Exchange(ctx context.Context, credential schema.Credential) (*schema.Identity, error) {
	if credential.Username == "" || credential.Password == "" {
		return nil, httpresponse.ErrBadRequest.With("A username and password are needed")
	}
	refused := httpresponse.ErrNotAuthorized.With("The username or password isn't right")
	user, err := p.manager.GetUser(ctx, credential.Username)
	if errors.Is(err, httpresponse.ErrNotFound) {
		return nil, refused
	} else if err != nil {
		return nil, err
	}
	if _, err := p.manager.Bind(ctx, user.DN, credential.Password); errors.Is(err, httpresponse.ErrNotAuthorized) {
		return nil, refused
	} else if err != nil {
		return nil, err
	}

	// The identity, and its groups, when the manager has them
	identity := &schema.Identity{
		Provider: p.meta.Name,
		Issuer:   p.issuer(),
		Subject:  user.DN,
		Email:    types.Value(user.Get("mail")),
		Name:     types.Value(user.Get("displayName")),
		Claims:   map[string]any{"username": credential.Username},
	}
	if identity.Name == "" {
		identity.Name = types.Value(user.Get("cn"))
	}
	if p.manager.Status().GroupDN != "" {
		groups, err := p.manager.ListGroups(ctx, ldapschema.GroupListRequest{
			ListRequest: ldapschema.ListRequest{Attr: []string{"cn"}},
			User:        types.Ptr(credential.Username),
		})
		if err != nil {
			return nil, err
		}
		for _, group := range groups.Body {
			if cn := group.Get("cn"); cn != nil {
				identity.Groups = append(identity.Groups, *cn)
			}
		}
	}
	return identity, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// issuer is the directory's URL, of its base DN, such as
// ldap://ldap.example.com:389/dc=example,dc=com
func (p *Provider) issuer() string {
	status := p.manager.Status()
	u := url.URL{Scheme: "ldap", Host: fmt.Sprintf("%s:%d", status.Host, status.Port), Path: "/" + status.BaseDN}
	return u.String()
}
