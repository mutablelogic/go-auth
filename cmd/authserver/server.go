//go:build !client

package main

import (
	"context"
	"crypto/rsa"
	"fmt"
	"net"
	"strings"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	httphandler "github.com/djthorpe/go-auth/pkg/httphandler"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	types "github.com/mutablelogic/go-server/pkg/types"
	errgroup "golang.org/x/sync/errgroup"
)

const (
	defaultCleanupInterval = time.Hour
	defaultCleanupLimit    = 100
)

type ServerCommands struct {
	RunServer RunServer `cmd:"" name:"run" help:"Run server." group:"SERVER"`
}

type RunServer struct {
	cmd.RunServer
	PostgresFlags
	CleanupFlags `embed:"" prefix:"cleanup."`
	GoogleFlags  `embed:"" prefix:"google."`
	Auth         bool `name:"auth" help:"Whether to enable authentication for protected endpoints." default:"true" negatable:""`
}

type CleanupFlags struct {
	Interval time.Duration `name:"interval" help:"How often to prune stale sessions." default:"1h"`
	Limit    int           `name:"limit" help:"Maximum stale sessions to prune in one pass." default:"100"`
}

type GoogleFlags struct {
	ClientID     string `name:"client-id" env:"GOOGLE_CLIENT_ID" help:"Google OAuth client ID exposed via /auth/config."`
	ClientSecret string `name:"client-secret" env:"GOOGLE_CLIENT_SECRET" help:"Google OAuth client secret kept server-side."`
}

type contextCmd struct {
	server.Cmd
	ctx context.Context
}

///////////////////////////////////////////////////////////////////////////////
// COMMANDS

func (server *RunServer) Run(ctx server.Cmd) error {
	return server.WithManager(ctx, func(manager *manager.Manager, v string) error {
		baseCtx, cancel := context.WithCancel(ctx.Context())
		defer cancel()

		group, groupCtx := errgroup.WithContext(baseCtx)
		runCtx := contextCmd{Cmd: ctx, ctx: groupCtx}

		// Register HTTP handlers
		server.RunServer.Register(func(router *httprouter.Router) error {
			return httphandler.RegisterHandlers(manager, router, server.Auth)
		})

		group.Go(func() error {
			defer cancel()
			return manager.Run(groupCtx)
		})

		group.Go(func() error {
			defer cancel()
			return server.RunServer.Run(runCtx)
		})

		return group.Wait()
	})
}

// WithManager creates the resource manager, registers all resource instances
// (logger, otel, handlers, router) in dependency order, invokes fn, then
// closes the manager regardless of whether fn returned an error.
func (server *RunServer) WithManager(ctx server.Cmd, fn func(*manager.Manager, string) error) error {
	// Connect to the database, if configured
	conn, err := server.Connect(ctx)
	if err != nil {
		return err
	} else if conn == nil {
		return fmt.Errorf("database connection is required")
	}

	// Create a private key, used for signing tokens
	pem := ctx.GetString("privatekey")
	var key *rsa.PrivateKey
	if pem == "" {
		key, err = authcrypto.GeneratePrivateKey()
		if err != nil {
			return fmt.Errorf("generate private key: %w", err)
		}
		pem, err = authcrypto.PrivateKeyPEM(key)
		if err != nil {
			return fmt.Errorf("marshal private key: %w", err)
		}
		if err := ctx.Set("privatekey", pem); err != nil {
			return fmt.Errorf("set private key: %w", err)
		}
	} else {
		key, err = authcrypto.ParsePrivateKeyPEM(pem)
		if err != nil {
			return fmt.Errorf("parse private key: %w", err)
		}
	}

	// Auth manager options
	opts := []manager.Opt{
		manager.WithPrivateKey(key),
	}
	issuer := server.issuer(ctx)
	if issuer == "" {
		return fmt.Errorf("issuer could not be determined from server configuration")
	}
	opts = append(opts, manager.WithOAuthClient(oidc.OAuthClientKeyLocal, issuer, "", ""))
	if clientID, clientSecret := strings.TrimSpace(server.GoogleFlags.ClientID), strings.TrimSpace(server.GoogleFlags.ClientSecret); clientID != "" || clientSecret != "" {
		opts = append(opts, manager.WithOAuthClient("google", oidc.GoogleIssuer, clientID, clientSecret))
	}
	opts = append(opts, manager.WithCleanup(server.cleanupInterval(), server.cleanupLimit()))

	// Add a hook for when a new user is created, to set the default metadata
	opts = append(opts, manager.WithUserHook(func(_ context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
		ctx.Logger().Info("Creating new user", "identity", identity, "meta", meta)

		// Set status to active
		if meta.Status == nil {
			meta.Status = types.Ptr(schema.UserStatusActive)
		}

		// Return the modified metadata, or an error to reject the user creation
		return meta, nil
	}))

	// Create the manager and run the server
	manager, err := manager.New(ctx.Context(), conn, opts...)
	if err != nil {
		return err
	}
	defer manager.Close()

	// Invoke the function with the manager and version string
	return fn(manager, "v1")
}

func (server *RunServer) issuer(ctx server.Cmd) string {
	scheme := "http"
	if server.TLS.CertFile != "" && server.TLS.KeyFile != "" {
		scheme = "https"
	}
	prefix := strings.TrimRight(ctx.HTTPPrefix(), "/")
	if origin := strings.TrimSpace(ctx.HTTPOrigin()); origin != "" && origin != "*" {
		return strings.TrimRight(origin, "/") + prefix
	}
	if hostport := publicHostPort(strings.TrimSpace(ctx.HTTPAddr())); hostport != "" {
		return scheme + "://" + hostport + prefix
	}
	return ""
}

func publicHostPort(addr string) string {
	if addr == "" {
		return ""
	}
	if strings.HasPrefix(addr, ":") {
		return "localhost" + addr
	}
	host, port, err := net.SplitHostPort(addr)
	if err == nil {
		switch host {
		case "", "0.0.0.0", "::":
			host = "localhost"
		}
		return net.JoinHostPort(host, port)
	}
	return addr
}

func (server *RunServer) cleanupInterval() time.Duration {
	if server.CleanupFlags.Interval > 0 {
		return server.CleanupFlags.Interval
	}
	return defaultCleanupInterval
}

func (server *RunServer) cleanupLimit() int {
	if server.CleanupFlags.Limit > 0 {
		return server.CleanupFlags.Limit
	}
	return defaultCleanupLimit
}

func (cmd contextCmd) Context() context.Context {
	return cmd.ctx
}
