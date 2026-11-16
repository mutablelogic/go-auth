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
	"context"
	"errors"
	"slices"
	"strings"

	// Packages
	goldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	store "github.com/mutablelogic/go-auth/auth/store"
	ldapschema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Users are the directory's users, as a user store, whose scopes are their
// groups'
type Users struct {
	manager Manager
	scopes  map[string][]string // by group, in lower case
}

var _ store.UserStore = (*Users)(nil)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewUsers returns the users of the manager's directory, whose scopes are
// those of the groups they're in, which scopes has, by the groups' names,
// in any case
func NewUsers(manager Manager, scopes map[string][]string) (*Users, error) {
	if manager == nil {
		return nil, httpresponse.ErrBadRequest.With("LDAP users need a manager")
	} else if manager.Status().UserDN == "" {
		return nil, httpresponse.ErrBadRequest.With("LDAP users need a users' DN")
	}
	self := &Users{manager: manager, scopes: make(map[string][]string, len(scopes))}
	for group, groupScopes := range scopes {
		self.scopes[strings.ToLower(group)] = append(self.scopes[strings.ToLower(group)], groupScopes...)
	}
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// User returns the user an identity is: one which signed in with the
// directory, by its DN, when its identifier is still the identity's
// subject, so it isn't another user with the DN, or one from another
// provider, by its verified email address, which is one user's mail.
// Others aren't found.
func (u *Users) User(ctx context.Context, identity *schema.Identity) (*schema.User, error) {
	if identity == nil {
		return nil, httpresponse.ErrNotFound.With("No identity")
	}
	var entry *ldapschema.Object
	switch dn, _ := identity.Claims["dn"].(string); {
	case identity.Issuer == issuerOf(u.manager) && dn != "":
		found, err := u.manager.Get(ctx, dn)
		if err != nil {
			return nil, err
		}
		entry = found
	case identity.Email != "" && identity.EmailVerified:
		found, err := u.byEmail(ctx, identity.Email)
		if err != nil {
			return nil, err
		}
		entry = found
	default:
		return nil, httpresponse.ErrNotFound.With("The identity isn't the directory's, nor has a verified email address")
	}

	// The user, by its identifier, which, for the directory's identity, is
	// its subject, or else it's another user, with its DN
	id, err := subjectOf(ctx, u.manager, entry.DN)
	if err != nil {
		return nil, err
	} else if identity.Issuer == issuerOf(u.manager) && id != identity.Subject {
		return nil, httpresponse.ErrNotFound.With("The identity's user is no longer in the directory")
	}
	user := &schema.User{
		ID:    id,
		Name:  types.Value(entry.Get("displayName")),
		Email: types.Value(entry.Get("mail")),
	}
	if user.Name == "" {
		user.Name = types.Value(entry.Get("cn"))
	}
	if u.manager.Status().GroupDN != "" {
		name, err := rdnValue(entry.DN)
		if err != nil {
			return nil, err
		}
		if user.Groups, err = groupsOf(ctx, u.manager, name); err != nil {
			return nil, err
		}
	}
	return user, nil
}

// Scopes returns the scopes of the groups the user is in, once each, in
// order
func (u *Users) Scopes(_ context.Context, user *schema.User) ([]string, error) {
	var result []string
	for _, group := range user.Groups {
		for _, scope := range u.scopes[strings.ToLower(group)] {
			if !slices.Contains(result, scope) {
				result = append(result, scope)
			}
		}
	}
	slices.Sort(result)
	return result, nil
}

// ParseGroupScopes returns the scopes of groups, from values of
// group=scope,scope, such as admins=ldap:read,ldap:write
func ParseGroupScopes(values ...string) (map[string][]string, error) {
	result := make(map[string][]string, len(values))
	for _, value := range values {
		group, scopes, ok := strings.Cut(value, "=")
		if group = strings.TrimSpace(group); !ok || group == "" {
			return nil, httpresponse.ErrBadRequest.Withf("A group's scopes are group=scope,scope, not %q", value)
		}
		for _, scope := range strings.Split(scopes, ",") {
			if scope = strings.TrimSpace(scope); scope != "" {
				result[group] = append(result[group], scope)
			}
		}
	}
	return result, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// byEmail returns the user whose mail is the address, in any case, or not
// found, or a conflict, when there's more than one
func (u *Users) byEmail(ctx context.Context, email string) (*ldapschema.Object, error) {
	users, err := u.manager.ListUsers(ctx, ldapschema.UserListRequest{ListRequest: ldapschema.ListRequest{
		OffsetLimit: ldapschema.OffsetLimit{Limit: types.Ptr(uint64(2))},
		Filter:      types.Ptr("(mail=" + goldap.EscapeFilter(email) + ")"),
	}})
	if err != nil {
		return nil, err
	}
	switch len(users.Body) {
	case 0:
		return nil, httpresponse.ErrNotFound.Withf("No user's email address is %q", email)
	case 1:
		return users.Body[0], nil
	default:
		return nil, httpresponse.ErrConflict.Withf("More than one user's email address is %q", email)
	}
}

// rdnValue returns the value of the DN's first RDN, such as a user's name
func rdnValue(dn string) (string, error) {
	parsed, err := goldap.ParseDN(dn)
	if err != nil {
		return "", err
	} else if len(parsed.RDNs) == 0 || len(parsed.RDNs[0].Attributes) == 0 {
		return "", errors.New("the DN has no RDN")
	}
	return parsed.RDNs[0].Attributes[0].Value, nil
}
