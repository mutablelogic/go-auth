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

// Package test runs tests against LDAP directories, OpenLDAP, 389 DS and
// SMB LDS, with a manager connected to each. Each directory is in a
// container which starts when a test first needs it, and is shared by the
// package's tests, until they've all run. They need docker, and are skipped
// with -short. LDAP_TEST_SERVER chooses some of them, separated by commas,
// such as "openldap,389ds".
package test

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	pgtest "github.com/mutablelogic/go-pg/pkg/test"
	require "github.com/stretchr/testify/require"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Server is a directory which the tests run against
type Server struct {
	Name         string
	Image        string
	TLSPort      string
	BaseDN       string
	BindDN       string
	BindPassword string
	UserDN       string
	GroupDN      string
	Env          map[string]string

	// URL is the ldaps URL of the server's container, when it's started.
	// Its certificate isn't trusted.
	URL string

	// ConnectTimeout is how long the directory can take to accept a bind,
	// once its container has started
	ConnectTimeout time.Duration

	// options returns the container's options, such as its TLS files
	options func() ([]pgtest.Opt, error)

	// bootstrap prepares the directory, once it accepts a bind
	bootstrap func(context.Context, Server, *pgtest.Container, *ldap.Conn) error
}

// container is a server's container, which is started once
type container struct {
	once      sync.Once
	container *pgtest.Container
	url       string
	err       error
}

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// ServerEnv chooses the servers, by name, separated by commas
const ServerEnv = "LDAP_TEST_SERVER"

var (
	containersMu sync.Mutex
	containers   = map[string]*container{}
)

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// Main runs the tests, then stops the containers they started. It's called
// from a package's TestMain.
func Main(m *testing.M) {
	code := m.Run()
	ctx := context.Background()
	containersMu.Lock()
	for name, c := range containers {
		if c.container != nil {
			if err := c.container.Close(ctx); err != nil {
				fmt.Fprintf(os.Stderr, "closing %s: %v\n", name, err)
			}
		}
	}
	containersMu.Unlock()
	os.Exit(code)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ForEach runs the test against each chosen directory, as a subtest, with
// a new manager, bound as the server's user, with the options, which is
// disconnected after it. It's skipped with -short.
func ForEach(t *testing.T, fn func(t *testing.T, ctx context.Context, server Server, manager *manager.Manager), opts ...manager.Opt) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping LDAP integration test with -short")
	}
	for _, server := range Servers(t) {
		t.Run(server.Name, func(t *testing.T) {
			ctx := context.Background()
			server.URL = start(t, server)
			fn(t, ctx, server, Manager(t, ctx, server, opts...))
		})
	}
}

// Manager returns a manager of the started server, bound as its user, with
// the options, which is disconnected when the test ends
func Manager(t *testing.T, ctx context.Context, server Server, opts ...manager.Opt) *manager.Manager {
	t.Helper()
	m, err := manager.New(append([]manager.Opt{
		manager.WithUrl(server.URL),
		manager.WithBaseDN(server.BaseDN),
		manager.WithUser(server.BindDN),
		manager.WithPassword(server.BindPassword),
		manager.WithUserDN(server.UserDN),
		manager.WithGroupDN(server.GroupDN),
		manager.WithSkipVerify(),
	}, opts...)...)
	require.NoError(t, err)
	t.Cleanup(func() { _ = m.Disconnect(context.WithoutCancel(ctx)) })

	// The directory accepted a bind when it started, so this is quick.
	// Connect closes its connection when the context ends.
	connectCtx, cancel := context.WithTimeout(ctx, server.ConnectTimeout)
	defer cancel()
	require.NoError(t, m.Connect(connectCtx), "connecting to %s", server.Name)
	return m
}

// Servers returns the servers which LDAP_TEST_SERVER names, or all of
// them, when it's not set
func Servers(t *testing.T) []Server {
	t.Helper()
	names := strings.TrimSpace(os.Getenv(ServerEnv))
	if names == "" {
		return servers
	}
	result := []Server{}
	for _, name := range strings.Split(names, ",") {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		found := false
		for _, server := range servers {
			if server.Name == name {
				result = append(result, server)
				found = true
			}
		}
		if !found {
			t.Fatalf("%s: unknown LDAP test server %q", ServerEnv, name)
		}
	}
	return result
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// start starts the server's container, once, and returns its ldaps URL, or
// fails the test when it can't be started
func start(t *testing.T, server Server) string {
	t.Helper()
	containersMu.Lock()
	c, exists := containers[server.Name]
	if !exists {
		c = new(container)
		containers[server.Name] = c
	}
	containersMu.Unlock()

	c.once.Do(func() {
		c.container, c.url, c.err = startContainer(context.Background(), server)
	})
	require.NoError(t, c.err, "starting %s", server.Name)
	return c.url
}

// startContainer starts the container, waits until the directory accepts a
// bind, and prepares it
func startContainer(ctx context.Context, server Server) (*pgtest.Container, string, error) {
	opts := []pgtest.Opt{pgtest.OptPorts(server.TLSPort)}
	if server.options != nil {
		more, err := server.options()
		if err != nil {
			return nil, "", err
		}
		opts = append(opts, more...)
	}
	for key, value := range server.Env {
		opts = append(opts, pgtest.OptEnv(key, value))
	}

	c, err := pgtest.NewContainer(ctx, "ldaptest_"+server.Name, server.Image, opts...)
	if err != nil {
		return nil, "", err
	}
	port, err := c.GetPort(server.TLSPort)
	if err != nil {
		return c, "", err
	}
	url := fmt.Sprintf("%s://127.0.0.1:%s", schema.MethodSecure, port)

	// The port listens before the directory binds, so it's retried
	conn, err := bindWithin(ctx, server, url, server.ConnectTimeout)
	if err != nil {
		return c, "", err
	}
	defer conn.Close()
	if server.bootstrap != nil {
		if err := server.bootstrap(ctx, server, c, conn); err != nil {
			return c, "", err
		}
	}
	return c, url, nil
}

// bindWithin connects and binds as the server's user, retrying until the
// timeout. Each attempt is bounded, so a stalled bind can't outlast it.
func bindWithin(ctx context.Context, server Server, url string, timeout time.Duration) (*ldap.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	for {
		conn, err := bind(server, url, time.Until(deadline(ctx)))
		if err == nil {
			return conn, nil
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%s: no bind within %v: %w", server.Name, timeout, err)
		case <-time.After(250 * time.Millisecond):
		}
	}
}

// bind connects and binds as the server's user, with each step bounded by
// the timeout
func bind(server Server, url string, timeout time.Duration) (*ldap.Conn, error) {
	timeout = max(timeout, time.Second)
	conn, err := ldap.DialURL(url,
		ldap.DialWithDialer(&net.Dialer{Timeout: timeout}),
		ldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: true}),
	)
	if err != nil {
		return nil, err
	}
	conn.SetTimeout(timeout)
	if err := conn.Bind(server.BindDN, server.BindPassword); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// deadline returns the context's deadline
func deadline(ctx context.Context) time.Time {
	d, _ := ctx.Deadline()
	return d
}
