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
	"fmt"

	// Packages
	authhandler "github.com/mutablelogic/go-auth/auth/httphandler"
	auth "github.com/mutablelogic/go-auth/auth/manager"
	cert "github.com/mutablelogic/go-auth/cert/manager"
	ldap "github.com/mutablelogic/go-auth/ldap/manager"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type ServerCommands struct {
	Run       AuthServer    `cmd:"" name:"run" help:"Run the authentication server." group:"SERVER"`
	Bootstrap BootstrapCert `cmd:"" name:"bootstrap" help:"Bootstrap by importing a root certificate PEM bundle." group:"SERVER"`
	cmd.OpenAPICommands
}

type AuthServer struct {
	cmd.RunServer
	PostgresFlags       `embed:"" prefix:"pg."`
	LDAPFlags           `embed:"" prefix:"ldap."`
	CertFlags           `embed:"" prefix:"cert."`
	AuthFlags           `embed:"" prefix:"auth."`
	LocalProviderFlags  `embed:"" prefix:"local."`
	GoogleProviderFlags `embed:"" prefix:"google."`
	UI                  bool `name:"ui" help:"Whether to serve the embedded web user interface" default:"true" negatable:""`
}

type BootstrapCert struct {
	BootstrapFlags `embed:""`
	PostgresFlags  `embed:"" prefix:"pg."`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (cmd *BootstrapCert) Run(ctx server.Cmd) error {
	ctx.Logger().DebugContext(ctx.Context(), "Connecting to database", "name", ctx.Name(), "version", ctx.Version())
	pool, err := cmd.PostgresFlags.Connect(ctx)
	if err != nil {
		return err
	} else if pool == nil {
		return fmt.Errorf("No database connection URL provided")
	}
	defer pool.Close()

	return cmd.WithCertManager(ctx, pool, func(certmanager *cert.Manager) error {
		ctx.Logger().InfoContext(ctx.Context(), "Imported root certificate from PEM bundle")
		return nil
	})
}

func (cmd *AuthServer) Run(ctx server.Cmd) error {
	ctx.Logger().DebugContext(ctx.Context(), "Connecting to database", "name", ctx.Name(), "version", ctx.Version())
	pool, err := cmd.PostgresFlags.Connect(ctx)
	if err != nil {
		return err
	} else if pool == nil {
		return fmt.Errorf("No database connection URL provided")
	}
	defer pool.Close()

	// Create an auth manager in the inner context
	return cmd.WithAuthManager(ctx, pool, func(authmanager *auth.Manager) error {
		return cmd.WithCertManager(ctx, pool, func(certmanager *cert.Manager) error {
			return cmd.WithLDAPManager(ctx, pool, func(ldapmanager *ldap.Manager) error {
				errgroup, errctx := errgroup.WithContext(ctx.Context())

				// Log the startup message
				ctx.Logger().InfoContext(ctx.Context(), "Started", "name", ctx.Name(), "version", ctx.Version())
				if authmanager != nil {
					if issuer, err := authmanager.OIDCIssuer(); err == nil {
						ctx.Logger().InfoContext(ctx.Context(), "OIDC Issuer", "issuer", issuer)
					}
					if signers, err := authmanager.OIDCJWKSet(); err == nil && signers.Len() > 0 {
						ctx.Logger().InfoContext(ctx.Context(), "OIDC Signers", "signers", signers.Keys(ctx.Context()))
					}
					if providers := authmanager.ProviderKeys(); len(providers) > 0 {
						ctx.Logger().InfoContext(ctx.Context(), "Identity Providers", "providers", providers)
					}
				}

				// Run the auth manager
				if authmanager != nil {
					ctx.Logger().DebugContext(ctx.Context(), "Running the Auth manager")
					errgroup.Go(func() error {
						return authmanager.Run(errctx)
					})
				}

				// Run the ldap manager
				if ldapmanager != nil {
					ctx.Logger().DebugContext(ctx.Context(), "Running the LDAP manager")
					errgroup.Go(func() error {
						return ldapmanager.Run(errctx, ctx.Logger())
					})
				}

				// Run the http server
				errgroup.Go(func() error {
					return cmd.RunServer.Run(ctx)
				})

				// Add the UI handlers if enabled
				if cmd.UI {
					ctx.Logger().WarnContext(ctx.Context(), "User Interface Enabled")
					cmd.RunServer.Register(func(router *httprouter.Router) error {
						return registerUIHandlers(router)
					})
				}

				// Run all the goroutines until one errors, and return any errors
				return errgroup.Wait()
			})
		})
	})
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - AUTH MANAGER

func (cmd *AuthServer) WithAuthManager(ctx server.Cmd, conn pg.PoolConn, fn func(manager *auth.Manager) error) error {
	// Get auth server options
	opts, signer, err := cmd.AuthFlags.Options(ctx)
	if err != nil {
		return err
	}
	if opts == nil {
		return fn(nil)
	}

	// Add google provider
	if provider, err := cmd.GoogleProviderFlags.NewProvider(); err != nil {
		return err
	} else if provider != nil {
		opts = append(opts, auth.WithProvider(provider))
	}

	// Add local provider - without signing
	if provider, err := cmd.LocalProviderFlags.NewProvider(signer, cmd.Issuer.String()); err != nil {
		return err
	} else if provider != nil {
		opts = append(opts, auth.WithProvider(provider))
	}

	// Create the auth manager
	ctx.Logger().DebugContext(ctx.Context(), "Creating Auth manager")
	manager, err := auth.New(ctx.Context(), conn, opts...)
	if err != nil {
		return err
	}

	// Register the HTTP handler routes
	cmd.RunServer.Register(
		authhandler.RegisterAuthHandlers(manager),
		authhandler.RegisterProviderHandlers(manager),
		authhandler.RegisterManagerHandlers(manager, cmd.AuthFlags.Enabled),
	)

	// Warn if auth is disabled
	if !cmd.AuthFlags.Enabled {
		ctx.Logger().WarnContext(ctx.Context(), "Authentication is disabled")
	}

	// Next callback in the chain
	return fn(manager)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - CERT MANAGER

func (cmd *AuthServer) WithCertManager(ctx server.Cmd, conn pg.PoolConn, fn func(manager *cert.Manager) error) error {
	opts := cmd.CertFlags.Options(ctx)
	if opts == nil {
		return fn(nil)
	}

	// Create the cert manager
	ctx.Logger().DebugContext(ctx.Context(), "Creating Certificate manager")
	manager, err := cert.New(ctx.Context(), conn, opts...)
	if err != nil {
		return err
	}

	// TODO: Register the HTTP handler routes

	// Next callback in the chain
	return fn(manager)
}

func (cmd *BootstrapCert) WithCertManager(ctx server.Cmd, conn pg.PoolConn, fn func(manager *cert.Manager) error) error {
	opts, err := cmd.BootstrapFlags.Options(ctx)
	if err != nil {
		return err
	}
	if opts == nil {
		return fn(nil)
	}

	// Create the cert manager
	ctx.Logger().DebugContext(ctx.Context(), "Bootstrapping Certificate manager")
	manager, err := cert.New(ctx.Context(), conn, opts...)
	if err != nil {
		return err
	}

	// Next callback in the chain
	return fn(manager)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - LDAP MANAGER

func (cmd *AuthServer) WithLDAPManager(ctx server.Cmd, conn pg.PoolConn, fn func(manager *ldap.Manager) error) error {
	opts := cmd.LDAPFlags.Options(ctx)
	if opts == nil {
		return fn(nil)
	}

	// Create the LDAP manager
	ctx.Logger().DebugContext(ctx.Context(), "Creating LDAP manager")
	manager, err := ldap.New(opts...)
	if err != nil {
		return err
	}

	// TODO: Register the HTTP handler routes

	// Next callback in the chain
	return fn(manager)
}
