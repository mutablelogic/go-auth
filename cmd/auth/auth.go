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

package main

import (
	// Packages
	authhandler "github.com/mutablelogic/go-auth/auth/httphandler"
	provider "github.com/mutablelogic/go-auth/auth/provider"
	github "github.com/mutablelogic/go-auth/auth/provider/github"
	ldapprovider "github.com/mutablelogic/go-auth/auth/provider/ldap"
	oidc "github.com/mutablelogic/go-auth/auth/provider/oidc"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	credential "github.com/mutablelogic/go-auth/credential"
	client "github.com/mutablelogic/go-client"
	server "github.com/mutablelogic/go-server"
	config "github.com/mutablelogic/go-server/config"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// AuthFlags configure the providers which people sign in with. A
// provider's OAuth client is a credential, by its key, whose value is
// {"client_id": "...", "client_secret": "..."}, so its secret is stored
// encrypted.
type AuthFlags struct {
	URL    string            `name:"url" env:"${ENV_NAME}_AUTH_URL" help:"URL the server is reached at, which providers redirect back to, such as https://auth.example.com. Without it, it's the request's."`
	Google GoogleFlags       `embed:"" prefix:"google."`
	GitHub GitHubFlags       `embed:"" prefix:"github."`
	OIDC   OIDCProviderFlags `embed:"" prefix:"oidc."`
	LDAP   bool              `name:"ldap" env:"${ENV_NAME}_AUTH_LDAP" help:"Sign in with the LDAP directory, with a username and password, when LDAP is built in"`
}

// GoogleFlags configure signing in with Google
type GoogleFlags struct {
	Credential string `name:"credential" help:"Key of the credential of the Google OAuth client, from the Google Cloud Console, to sign in with Google"`
}

// GitHubFlags configure signing in with GitHub
type GitHubFlags struct {
	Credential string `name:"credential" help:"Key of the credential of the GitHub OAuth app, to sign in with GitHub"`
	Orgs       bool   `name:"orgs" help:"Ask for the user's organisations, which are their groups"`
}

// OIDCProviderFlags configure signing in with another OpenID Connect issuer
type OIDCProviderFlags struct {
	Name        string   `name:"name" default:"oidc" help:"Name of the issuer, which is in its paths"`
	Label       string   `name:"label" help:"Label of the issuer, to show, such as Keycloak"`
	Issuer      string   `name:"issuer" help:"Issuer's URL, such as https://keycloak.example.com/realms/example, to sign in with it"`
	Credential  string   `name:"credential" help:"Key of the credential of the client, at the issuer"`
	Scopes      []string `name:"scope" help:"Scopes to ask for, other than openid, email and profile. Can be specified more than once."`
	GroupsClaim string   `name:"groups-claim" help:"Claim with the person's groups, such as groups"`
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// withHandlers calls fn with the registration of signing in with the
// providers which are configured, or without, when there are none. Their
// OAuth clients are credentials, and the directory is the LDAP manager,
// when LDAP is built in.
func (flags AuthFlags) withHandlers(ctx server.Cmd, credentials credential.CredentialProvider, directory ldapprovider.Manager, fn func(*module) error) error {
	providers, err := flags.providers(ctx, credentials, directory)
	if err != nil {
		return err
	} else if len(providers) == 0 {
		return fn(nil)
	}
	var opts []authhandler.Opt
	if flags.URL != "" {
		opts = append(opts, authhandler.WithBaseURL(flags.URL))
	}
	for _, p := range providers {
		ctx.Logger().InfoContext(ctx.Context(), "Sign in", "provider", p.Meta().Name)
	}

	// The configuration has the providers, for the sign-in page
	return fn(&module{
		register: authhandler.RegisterHandlers(providers, opts...),
		section:  config.WithSection("auth", schema.Config{Providers: authhandler.Providers(providers)}),
	})
}

// providers returns the providers which are configured: Google, GitHub,
// another OIDC issuer, and the LDAP directory, with clients which are
// traced. The credentials of their OAuth clients are checked, so one which
// isn't there, or isn't a client, stops the server.
func (flags AuthFlags) providers(ctx server.Cmd, credentials credential.CredentialProvider, directory ldapprovider.Manager) ([]provider.Provider, error) {
	var result []provider.Provider
	clientOpts := []client.ClientOpt{client.OptTracer(ctx.Tracer())}
	for _, key := range []string{flags.Google.Credential, flags.GitHub.Credential, flags.OIDC.Credential} {
		if key == "" {
			continue
		} else if _, err := provider.Client(ctx.Context(), credentials, key); err != nil {
			return nil, err
		}
	}
	if flags.Google.Credential != "" {
		p, err := oidc.NewGoogle(credentials, flags.Google.Credential, oidc.WithClient(clientOpts...))
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	if flags.GitHub.Credential != "" {
		opts := []github.Opt{github.WithClient(clientOpts...)}
		if flags.GitHub.Orgs {
			opts = append(opts, github.WithOrganizations())
		}
		p, err := github.New(credentials, flags.GitHub.Credential, opts...)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	if flags.OIDC.Issuer != "" {
		opts := []oidc.Opt{oidc.WithClient(clientOpts...), oidc.WithScopes(flags.OIDC.Scopes...)}
		if flags.OIDC.GroupsClaim != "" {
			opts = append(opts, oidc.WithGroupsClaim(flags.OIDC.GroupsClaim))
		}
		p, err := oidc.New(flags.OIDC.Name, flags.OIDC.Label, flags.OIDC.Issuer, credentials, flags.OIDC.Credential, opts...)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	if flags.LDAP {
		if directory == nil {
			return nil, httpresponse.ErrBadRequest.With("Signing in with LDAP needs LDAP, which isn't built in, or configured")
		}
		p, err := ldapprovider.New(directory)
		if err != nil {
			return nil, err
		}
		result = append(result, p)
	}
	return result, nil
}
