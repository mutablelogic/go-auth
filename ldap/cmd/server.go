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

//go:build !client

// Package ldap has the LDAP manager's command-line flags, for a server
package ldap

import (
	"context"
	"errors"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ServerFlags configure the LDAP manager: the directory, the user it binds
// as, and the DNs of its users and groups, which are passed to
// WithLDAPManager. They're embedded with a prefix, such as ldap.
type ServerFlags struct {
	URL        string   `name:"url" env:"${ENV_NAME}_LDAP_URL" help:"URL of the directory, ldap or ldaps, which can have the user and password, such as ldaps://cn=admin:password@ldap.example.com"`
	BaseDN     string   `name:"base-dn" env:"${ENV_NAME}_LDAP_BASE_DN" help:"Base DN, which every DN is under, such as dc=example,dc=com"`
	User       string   `name:"user" env:"${ENV_NAME}_LDAP_USER" help:"User to bind as, which is a DN, or a name under the base DN, rather than the URL's"`
	Password   string   `name:"password" env:"${ENV_NAME}_LDAP_PASSWORD" help:"Password of the user, rather than the URL's"`
	UserDN     string   `name:"user-dn" env:"${ENV_NAME}_LDAP_USER_DN" help:"DN of the users, relative to the base DN, such as ou=users. Without it, there are no users."`
	UserClass  []string `name:"user-class" env:"${ENV_NAME}_LDAP_USER_CLASS" help:"Object classes of new users. Without them, they're those the directory has, such as inetOrgPerson and posixAccount."`
	GroupDN    string   `name:"group-dn" env:"${ENV_NAME}_LDAP_GROUP_DN" help:"DN of the groups, relative to the base DN, such as ou=groups. Without it, there are no groups."`
	GroupClass []string `name:"group-class" env:"${ENV_NAME}_LDAP_GROUP_CLASS" help:"Object classes of new groups. Without them, they're those the directory has, such as groupOfNames and posixGroup."`
	SkipVerify bool     `name:"skip-verify" env:"${ENV_NAME}_LDAP_SKIP_VERIFY" help:"Don't verify the directory's TLS certificate"`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// WithLDAPManager creates the LDAP manager, with the command's tracer, and
// the publisher, such as go-server's broadcaster, when it isn't nil, which
// publishes its changes, and the manager's own options. It runs the
// manager, which connects, and reconnects when the connection is lost,
// and calls fn with it, then disconnects, when fn returns.
func (flags ServerFlags) WithLDAPManager(ctx server.Cmd, publisher manager.Publisher, fn func(*manager.Manager) error, opts ...manager.Opt) error {
	if flags.URL == "" {
		return auth.ErrBadParameter.With("LDAP needs the directory's URL: set --ldap.url")
	} else if flags.BaseDN == "" {
		return auth.ErrBadParameter.With("LDAP needs a base DN: set --ldap.base-dn")
	}

	// The options, with those of the flags which are set
	base := []manager.Opt{
		manager.WithUrl(flags.URL),
		manager.WithBaseDN(flags.BaseDN),
		manager.WithUser(flags.User),
		manager.WithPassword(flags.Password),
		manager.WithTracer(ctx.Tracer()),
	}
	if flags.UserDN != "" {
		base = append(base, manager.WithUserDN(flags.UserDN, flags.UserClass...))
	}
	if flags.GroupDN != "" {
		base = append(base, manager.WithGroupDN(flags.GroupDN, flags.GroupClass...))
	}
	if flags.SkipVerify {
		base = append(base, manager.WithSkipVerify())
	}
	if publisher != nil {
		base = append(base, manager.WithBroadcaster(publisher))
	}
	mgr, err := manager.New(append(base, opts...)...)
	if err != nil {
		return err
	}
	ctx.Logger().InfoContext(ctx.Context(), "LDAP", "host", mgr.Host(), "port", mgr.Port(), "user", mgr.User())

	// Run the manager while fn runs, and stop it, which disconnects, after
	runctx, cancel := context.WithCancel(ctx.Context())
	done := make(chan error, 1)
	go func() {
		done <- mgr.Run(runctx, ctx.Logger())
	}()
	err = fn(mgr)
	cancel()
	return errors.Join(err, <-done)
}
