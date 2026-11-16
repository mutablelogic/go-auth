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

// Package cmd has the commands which sign in to a server, in a browser,
// with OAuth, and keep the token, which the other commands send, with
// ClientEndpoint, and sign out.
package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"

	// Packages
	goauth "github.com/mutablelogic/go-auth"
	httpclient "github.com/mutablelogic/go-auth/auth/httpclient"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	client "github.com/mutablelogic/go-client"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	server "github.com/mutablelogic/go-server"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// AuthCommands sign in to the server, show the session, and sign out
type AuthCommands struct {
	Login   LoginCmd   `cmd:"" name:"login" help:"Sign in to the server, in a browser, and keep the token, which the other commands send." group:"AUTH"`
	Session SessionCmd `cmd:"" name:"session" help:"Show who's signed in, with the kept token." group:"AUTH"`
	Logout  LogoutCmd  `cmd:"" name:"logout" help:"Sign out, ending the session, and forget the token." group:"AUTH"`
}

type LoginCmd struct {
	Scopes    []string      `name:"scope" help:"Scopes to ask for. Without them, they're all the session's. Can be specified more than once."`
	NoBrowser bool          `name:"no-browser" help:"Print the URL to sign in at, rather than opening it in a browser."`
	Timeout   time.Duration `name:"wait" default:"5m" help:"How long to wait for signing in."`
}

type SessionCmd struct{}

type LogoutCmd struct{}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Run signs in: the server is discovered, the command registers, with a
// loopback callback, and is authorized, in a browser, and the token is kept
func (cmd *LoginCmd) Run(ctx server.Cmd) (err error) {
	endpoint, _, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	tokens, err := tokens(ctx)
	if err != nil {
		return err
	}
	c, err := httpclient.New(endpoint, secretOpts(ctx)...)
	if err != nil {
		return err
	}
	child, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), "auth.LoginCmd")
	defer func() { endSpan(err) }()
	wait, cancel := context.WithTimeout(child, cmd.Timeout)
	defer cancel()

	// Sign in, in the browser
	grant, err := c.Login(wait, nil, ctx.Name(), nil, func(url string) error {
		fmt.Fprintln(os.Stderr, "Sign in at:", url)
		if !cmd.NoBrowser {
			if err := browse(url); err != nil {
				fmt.Fprintln(os.Stderr, "The browser couldn't be opened:", err)
			}
		}
		return nil
	}, cmd.Scopes...)
	if errors.Is(err, context.DeadlineExceeded) {
		return goauth.ErrBadParameter.Withf("not signed in, within %v", cmd.Timeout)
	} else if err != nil {
		return err
	}
	if err := tokens.Set(endpoint, grant.Token); err != nil {
		return err
	}

	// Who's signed in
	session, err := getSession(child, ctx, endpoint)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "Signed in to %s as %s, until %s\n", endpoint, who(session), session.ExpiresAt.Local().Format(time.RFC1123))
	return nil
}

// Run shows the session of the kept token
func (cmd *SessionCmd) Run(ctx server.Cmd) (err error) {
	endpoint, _, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	child, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), "auth.SessionCmd")
	defer func() { endSpan(err) }()
	session, err := getSession(child, ctx, endpoint)
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		return err
	}
	fmt.Println(string(data))
	return nil
}

// Run ends the session of the kept token, and forgets it, which it does
// when the session has already ended
func (cmd *LogoutCmd) Run(ctx server.Cmd) (err error) {
	endpoint, _, err := ctx.ClientEndpoint()
	if err != nil {
		return err
	}
	tokens, err := tokens(ctx)
	if err != nil {
		return err
	}
	opts := TokenOpts(ctx, endpoint)
	if len(opts) == 0 {
		_ = tokens.Delete(endpoint)
		return fmt.Errorf("not signed in to %s", endpoint)
	}
	c, err := client.New(append(append(secretOpts(ctx), opts...), client.OptEndpoint(endpoint))...)
	if err != nil {
		return err
	}
	child, endSpan := otel.StartSpan(ctx.Tracer(), ctx.Context(), "auth.LogoutCmd")
	defer func() { endSpan(err) }()
	err = goauth.ClientError(c.DoWithContext(child, client.MethodPost, nil, client.OptPath("auth", "logout")))
	if err != nil && !errors.Is(err, goauth.ErrInvalidProvider) {
		return err
	}
	if err := tokens.Delete(endpoint); err != nil {
		return err
	}
	fmt.Fprintln(os.Stderr, "Signed out of", endpoint)
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// getSession returns the session of the kept token
func getSession(ctx context.Context, cmd server.Cmd, endpoint string) (*schema.Session, error) {
	opts := TokenOpts(cmd, endpoint)
	if len(opts) == 0 {
		return nil, fmt.Errorf("not signed in to %s: sign in with %s login", endpoint, cmd.Name())
	}
	c, err := client.New(append(append(secretOpts(cmd), opts...), client.OptEndpoint(endpoint))...)
	if err != nil {
		return nil, err
	}
	var session schema.Session
	if err := goauth.ClientError(c.DoWithContext(ctx, client.MethodGet, &session, client.OptPath("auth", "session"))); err != nil {
		return nil, err
	}
	return &session, nil
}

// secretOpts are the command's client options, without --verbose's trace,
// which would print the token, in a response's body, so --debug traces the
// requests, without their bodies
func secretOpts(ctx server.Cmd) []client.ClientOpt {
	opts := []client.ClientOpt{client.OptTracer(ctx.Tracer())}
	if timeout := ctx.HTTPTimeout(); timeout > 0 {
		opts = append(opts, client.OptTimeout(timeout))
	}
	if ctx.IsDebug() {
		opts = append(opts, client.OptTrace(os.Stderr, false))
	}
	return opts
}

// who is who's signed in: their name, or email address, or ID
func who(session *schema.Session) string {
	switch {
	case session.User.Name != "":
		return session.User.Name
	case session.User.Email != "":
		return session.User.Email
	default:
		return session.User.ID
	}
}

// browse opens the URL in a browser
func browse(url string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	default:
		return exec.Command("xdg-open", url).Start()
	}
}
