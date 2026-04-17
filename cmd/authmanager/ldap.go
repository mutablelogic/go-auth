package main

import (
	ldap "github.com/mutablelogic/go-auth/ldap/manager"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type LDAPFlags struct {
	URL     string `long:"url" description:"LDAP URL to listen on" env:"LDAP_URL" example:"ldap://localhost:389"`
	BaseDN  string `long:"base-dn" description:"Base DN for LDAP entries" default:"dc=example,dc=org" env:"LDAP_BASEDN"`
	User    string `long:"user" description:"Bind user DN for LDAP manager" default:"cn=admin,dc=example,dc=org" env:"LDAP_USER"`
	Pass    string `long:"pass" description:"Bind password for LDAP manager" env:"LDAP_PASS"`
	UserDN  string `long:"user-dn" description:"Relative DN for the user subtree (e.g. ou=users)" env:"LDAP_USER_DN" optional:""`
	GroupDN string `long:"group-dn" description:"Relative DN for the group subtree (e.g. ou=groups)" env:"LDAP_GROUP_DN" optional:""`
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (server LDAPFlags) Options(ctx server.Cmd) []ldap.Opt {
	// If the URL is not set return nil
	if server.URL == "" {
		return nil
	}

	// Set options based on flags
	opts := []ldap.Opt{
		ldap.WithUrl(server.URL),
		ldap.WithUser(server.User),
		ldap.WithPassword(server.Pass),
		ldap.WithBaseDN(server.BaseDN),
	}

	// Set user and group DNs if configured
	if server.GroupDN != "" {
		opts = append(opts, ldap.WithGroupDN(server.GroupDN))
	}
	if server.UserDN != "" {
		opts = append(opts, ldap.WithUserDN(server.UserDN))
	}

	// Return the options
	return opts
}
