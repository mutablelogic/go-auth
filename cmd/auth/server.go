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
	"context"

	// Packages
	ldapprovider "github.com/mutablelogic/go-auth/auth/provider/ldap"
	credential "github.com/mutablelogic/go-auth/credential"
	httphandler "github.com/mutablelogic/go-auth/credential/httphandler"
	frontend "github.com/mutablelogic/go-auth/frontend/cmd"
	pg "github.com/mutablelogic/go-pg"
	server "github.com/mutablelogic/go-server"
	broadcaster "github.com/mutablelogic/go-server/broadcaster"
	broadcastercmd "github.com/mutablelogic/go-server/broadcaster/cmd"
	broadcasterhandler "github.com/mutablelogic/go-server/broadcaster/httphandler"
	config "github.com/mutablelogic/go-server/config"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ServerCommands run the credential server, with the backend which the
// build tags select: file (the default), pg, aws or bitwarden
type ServerCommands struct {
	Run RunServer `cmd:"" name:"run" help:"Run the credential server." group:"SERVER"`
	cmd.OpenAPICommands
}

// openapiTag is the tag of the API's documentation, which go-server's
// openapi handler has
const openapiTag = "OpenAPI"

// registerFunc registers handlers with the router
type registerFunc func(*httprouter.Router) error

// module is a module of the server, which isn't always built in, such as
// certificates: its handlers, and its section of the configuration, which
// says what it can do, and that the web UI includes it, when it has one
type module struct {
	register registerFunc
	section  config.Opt
}

// follow follows the changes which PostgreSQL's triggers notify the channel
// of, and publishes them, whatever makes them: run follows them, until the
// context is cancelled, and ready waits until it does, so the server doesn't
// accept a change before it would be published
type follow struct {
	channel string
	run     func(context.Context) error
	ready   func(context.Context) error
}

// unnotified calls fn with a manager which doesn't notify of its changes,
// which the API publishes
func unnotified(fn func(credential.CredentialManager, bool) error) func(credential.CredentialManager) error {
	return func(manager credential.CredentialManager) error {
		return fn(manager, false)
	}
}

// RunServer runs the credential server, with its web UI, when it's built
// in, and the changes, which the UI follows the server with. The
// passphrases and the PostgreSQL connection are shared by the credential
// backend and, when it's built in, the certificate manager.
type RunServer struct {
	cmd.RunServer
	Passphrase  []string             `name:"passphrase" env:"${ENV_NAME}_PASSPHRASE" sep:"none" help:"Passphrase for encrypting credentials and private keys. Can be specified multiple times, for versions 1, 2 and so on, and the last is used for new ones."`
	Insecure    bool                 `name:"insecure" env:"${ENV_NAME}_INSECURE" help:"Serve the certificate and LDAP APIs, when they're built in, which have no authentication yet, so anyone who can reach the server can create certificates, get their private keys, and change the directory"`
	Postgres    PostgresFlags        `embed:"" prefix:"pg."`
	Credential  BackendFlags         `embed:"" prefix:"credential."`
	Cert        CertFlags            `embed:"" prefix:"cert."`
	LDAP        LDAPFlags            `embed:"" prefix:"ldap."`
	Auth        AuthFlags            `embed:"" prefix:"auth."`
	Broadcaster broadcastercmd.Flags `embed:"" prefix:"broadcaster."`
	Frontend    frontend.Flags       `embed:""`
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (runner *RunServer) Run(ctx server.Cmd) error {
	return runner.Broadcaster.WithBroadcaster(ctx, &runner.RunServer, func(changes *broadcaster.Broadcaster) error {
		return runner.Postgres.withPool(ctx, changes, func(pool pg.PoolConn, follow *follow) error {
			return runner.Credential.withManager(ctx, pool, follow, runner.Passphrase, func(manager credential.CredentialManager, notified bool) error {
				ctx.Logger().InfoContext(ctx.Context(), "Credentials", "backend", backend)
				ctx.Logger().WarnContext(ctx.Context(), "The credential API has no authentication")
				return runner.Cert.withHandlers(ctx, pool, follow, runner.Passphrase, runner.Insecure, func(certs *module) error {
					return runner.LDAP.withHandlers(ctx, changes, runner.Insecure, func(ldap *module, directory ldapprovider.Manager) error {
						return runner.Auth.withHandlers(ctx, directory, func(signin *module) error {
							// The API publishes its changes, unless the
							// backend's trigger notifies of them, as pg's does
							var publisher httphandler.Publisher
							if !notified {
								publisher = changes
							}
							runner.register(ctx, manager, publisher, certs, ldap, signin)
							return runner.run(ctx, changes, follow)
						})
					})
				})
			})
		})
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// register registers the configuration, with what the credential manager
// can do, which depends on its backend, the web UI, when it's served, or
// else a handler of / which isn't found, the credential API, which
// publishes its changes, which the UI follows, and the modules' APIs, such
// as certificates' and LDAP's, when they're built in
func (runner *RunServer) register(ctx server.Cmd, manager credential.CredentialManager, publisher httphandler.Publisher, modules ...*module) {
	runner.RunServer.Register(func(router *httprouter.Router) error {
		sections := []config.Opt{config.WithSection("credential", credential.FeaturesOf(backend, manager))}
		for _, module := range modules {
			if module != nil && module.section != nil {
				sections = append(sections, module.section)
			}
		}
		ui, err := runner.Frontend.RegisterUI(ctx, ctx.Logger(), router, runner.RunServer.OpenAPI, sections...)
		if err != nil {
			return err
		}
		if !ui {
			if err := router.RegisterCatchAll("/", true); err != nil {
				return err
			}
		}
		var opts []httphandler.Opt
		if publisher != nil {
			opts = append(opts, httphandler.WithPublisher(publisher))
		}
		if err := httphandler.RegisterManagerHandlers(manager, false, opts...)(router); err != nil {
			return err
		}
		for _, module := range modules {
			if module != nil {
				if err := module.register(router); err != nil {
					return err
				}
			}
		}

		// The configuration, the API's documentation, and the changes, which
		// the web UI uses, are a tag group, after the credentials', as Redoc
		// doesn't show a tag which isn't in one
		router.Spec().AddTagGroup("UI", config.Tag, openapiTag, broadcasterhandler.Tag)
		return nil
	})
}

// run runs the broadcaster, the follower of PostgreSQL's changes, when
// there's a database, and the server, until any of them stops. The server starts once
// the follower is ready, so no change is accepted before it would be
// published, and doesn't start when the follower fails.
func (runner *RunServer) run(ctx server.Cmd, changes *broadcaster.Broadcaster, follow *follow) error {
	group, groupctx := errgroup.WithContext(ctx.Context())
	group.Go(func() error {
		return changes.Run(groupctx)
	})
	if follow != nil {
		group.Go(func() error {
			return follow.run(groupctx)
		})
	}
	group.Go(func() error {
		if follow != nil {
			if err := follow.ready(groupctx); err != nil {
				return err
			}
		}
		return runner.RunServer.Run(ctx.WithContext(groupctx))
	})
	return group.Wait()
}
