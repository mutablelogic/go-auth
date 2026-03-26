//go:build !client

package main

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"

	// Packages
	authcrypto "github.com/djthorpe/go-auth/pkg/crypto"
	authhandler "github.com/djthorpe/go-auth/pkg/httphandler/auth"
	managerhandler "github.com/djthorpe/go-auth/pkg/httphandler/manager"
	manager "github.com/djthorpe/go-auth/pkg/manager"
	oidc "github.com/djthorpe/go-auth/pkg/oidc"
	schema "github.com/djthorpe/go-auth/schema"
	server "github.com/mutablelogic/go-server"
	cmd "github.com/mutablelogic/go-server/pkg/cmd"
	httprouter "github.com/mutablelogic/go-server/pkg/httprouter"
	types "github.com/mutablelogic/go-server/pkg/types"
	errgroup "golang.org/x/sync/errgroup"
)

type ServerCommands struct {
	RunServer RunServer `cmd:"" name:"run" help:"Run server." group:"SERVER"`
}

type RunServer struct {
	cmd.RunServer
	PostgresFlags
	CleanupFlags  `embed:"" prefix:"cleanup."`
	GoogleFlags   `embed:"" prefix:"google."`
	NotifyChannel string `name:"notify-channel" help:"PostgreSQL LISTEN/NOTIFY channel for table change streaming. Empty disables change notifications." default:"backend.table_change"`
	Auth          bool   `name:"auth" help:"Whether to enable authentication for protected endpoints." default:"true" negatable:""`
	UI            bool   `name:"ui" help:"Whether to serve the embedded web user interface" default:"true" negatable:""`
}

type CleanupFlags struct {
	Interval time.Duration `name:"interval" help:"How often to prune stale sessions. Defaults to the manager default when unset."`
	Limit    int           `name:"limit" help:"Maximum stale sessions to prune in one pass. Defaults to the manager default when unset."`
}

type GoogleFlags struct {
	ClientID     string `name:"client-id" env:"GOOGLE_CLIENT_ID" help:"Google OAuth client ID exposed via /auth/config."`
	ClientSecret string `name:"client-secret" env:"GOOGLE_CLIENT_SECRET" help:"Google OAuth client secret kept server-side."`
}

type contextCmd struct {
	server.Cmd
	ctx context.Context
}

type newUserHooks struct {
	logger func(string, ...any)
}

func (h newUserHooks) OnUserCreate(_ context.Context, identity schema.IdentityInsert, meta schema.UserMeta) (schema.UserMeta, error) {
	h.logger("Creating new user", "identity", identity, "meta", meta)

	if meta.Status == nil {
		meta.Status = types.Ptr(schema.UserStatusActive)
	}

	return meta, nil
}

func (h newUserHooks) OnIdentityLink(_ context.Context, identity schema.IdentityInsert, existing *schema.User) error {
	h.logger("Linking identity to existing user", "identity", identity, "user", existing)

	// Check email addresses match exactly
	if identity.Email != existing.Email {
		return fmt.Errorf("identity email does not match existing user email")
	}

	// Allow the link to proceed without error, but do not modify the existing user
	return nil
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
			var result error
			result = errors.Join(result, managerhandler.RegisterManagerHandlers(manager, router, server.Auth))
			result = errors.Join(result, authhandler.RegisterAuthHandlers(manager, router))
			if server.UI {
				result = errors.Join(result, registerUIHandlers(router))
			}
			return result
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
	opts = append(opts, manager.WithOAuthClient(schema.OAuthClientKeyLocal, issuer, "", ""))
	if clientID, clientSecret := strings.TrimSpace(server.GoogleFlags.ClientID), strings.TrimSpace(server.GoogleFlags.ClientSecret); clientID != "" || clientSecret != "" {
		opts = append(opts, manager.WithOAuthClient("google", oidc.GoogleIssuer, clientID, clientSecret))
	}
	if channel := strings.TrimSpace(server.NotifyChannel); channel != "" {
		opts = append(opts, manager.WithNotificationChannel(channel))
	}
	opts = append(opts, manager.WithCleanup(server.CleanupFlags.Interval, server.CleanupFlags.Limit))

	// Add hooks for login-time user provisioning behavior.
	opts = append(opts, manager.WithHooks(newUserHooks{logger: ctx.Logger().Info}))

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

func (cmd contextCmd) Context() context.Context {
	return cmd.ctx
}
