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
	Get(ctx context.Context, dn string, attrs ...string) (*ldapschema.Object, error)
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
// GLOBALS

// identifiers are the attributes which identify an entry, and don't change,
// in the order they're used, of OpenLDAP, 389 DS and Active Directory
var identifiers = []string{"entryUUID", "nsUniqueId", "objectGUID"}

// groupsPage is how many of a user's groups are listed at a time
const groupsPage = uint64(500)

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

	// The identity, by the user's identifier, which doesn't change when
	// it's renamed, and isn't another user's when it's deleted, and its
	// groups, when the manager has them
	subject, err := p.subject(ctx, user.DN)
	if err != nil {
		return nil, err
	}
	identity := &schema.Identity{
		Provider: p.meta.Name,
		Issuer:   p.issuer(),
		Subject:  subject,
		Email:    types.Value(user.Get("mail")),
		Name:     types.Value(user.Get("displayName")),
		Claims:   map[string]any{"username": credential.Username, "dn": user.DN},
	}
	if identity.Name == "" {
		identity.Name = types.Value(user.Get("cn"))
	}
	if p.manager.Status().GroupDN != "" {
		groups, err := p.groups(ctx, credential.Username)
		if err != nil {
			return nil, err
		}
		identity.Groups = groups
	}
	return identity, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// subject returns the user's identifier, which the directory gives each
// entry, and doesn't change: entryUUID, which OpenLDAP has, nsUniqueId,
// which 389 DS has, or objectGUID, which Active Directory has, or else its
// DN, when the directory has none of them
func (p *Provider) subject(ctx context.Context, dn string) (string, error) {
	entry, err := p.manager.Get(ctx, dn, identifiers...)
	if err != nil {
		return "", err
	}
	for _, attr := range identifiers {
		if value := types.Value(entry.Get(attr)); value != "" {
			if attr == "objectGUID" {
				return formatGUID([]byte(value)), nil
			}
			return value, nil
		}
	}
	return dn, nil
}

// groups returns the names of every group the user is in, a page at a time
func (p *Provider) groups(ctx context.Context, username string) ([]string, error) {
	var result []string
	for offset := uint64(0); ; {
		page, err := p.manager.ListGroups(ctx, ldapschema.GroupListRequest{
			ListRequest: ldapschema.ListRequest{OffsetLimit: ldapschema.OffsetLimit{Offset: offset, Limit: types.Ptr(groupsPage)}, Attr: []string{"cn"}},
			User:        types.Ptr(username),
		})
		if err != nil {
			return nil, err
		}
		for _, group := range page.Body {
			if cn := group.Get("cn"); cn != nil {
				result = append(result, *cn)
			}
		}
		offset += uint64(len(page.Body))
		if len(page.Body) == 0 || offset >= page.Count {
			return result, nil
		}
	}
}

// formatGUID returns Active Directory's objectGUID, which is binary, as
// its string, whose first three parts are little-endian
func formatGUID(b []byte) string {
	if len(b) != 16 {
		return fmt.Sprintf("%x", b)
	}
	return fmt.Sprintf("%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		b[3], b[2], b[1], b[0], b[5], b[4], b[7], b[6], b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}

// issuer is the directory's URL, of its base DN, such as
// ldap://ldap.example.com:389/dc=example,dc=com
func (p *Provider) issuer() string {
	status := p.manager.Status()
	u := url.URL{Scheme: "ldap", Host: fmt.Sprintf("%s:%d", status.Host, status.Port), Path: "/" + status.BaseDN}
	return u.String()
}
