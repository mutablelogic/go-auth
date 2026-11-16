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
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"net"
	"os"
	"sort"
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

	// ActiveDirectory is true when the directory is Active Directory, or
	// like it, whose users have the "user" class, and unicodePwd passwords
	ActiveDirectory bool

	// KeepsOldPassword is true when a user's old password still binds for
	// a while after it's changed, as Samba's "old password allowed period"
	// does, for an hour
	KeepsOldPassword bool

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

// OU creates an organizational unit for the test, with a random name, under
// the base DN, and returns its DN. It's deleted when the test ends, with
// the entries under it.
func OU(t *testing.T, ctx context.Context, m *manager.Manager) string {
	t.Helper()
	dn := "ou=test-" + strings.ToLower(rand.Text()[:10])
	ou, err := m.Create(ctx, dn, schema.Attrs{
		"objectClass": {"top", "organizationalUnit"},
		"ou":          {strings.TrimPrefix(dn, "ou=")},
	})
	require.NoError(t, err)
	t.Cleanup(func() {
		if err := deleteTree(context.WithoutCancel(ctx), m, ou.DN); err != nil {
			t.Errorf("deleting %s: %v", ou.DN, err)
		}
	})
	return ou.DN
}

// Attribute returns the entry's values of the attribute, as the started
// server has them, read with go-ldap, not the manager, which hides some
func Attribute(t *testing.T, server Server, dn, name string) []string {
	t.Helper()
	conn, err := bind(server, server.URL, server.ConnectTimeout)
	require.NoError(t, err)
	defer conn.Close()
	result, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{name}, nil))
	require.NoError(t, err)
	require.Len(t, result.Entries, 1)
	return result.Entries[0].GetAttributeValues(name)
}

// Subschema returns the definitions of the started server's object classes
// and attribute types, as it has them, read with go-ldap, not the manager
func Subschema(t *testing.T, server Server) (classes, attrs []string) {
	t.Helper()
	conn, err := bind(server, server.URL, server.ConnectTimeout)
	require.NoError(t, err)
	defer conn.Close()

	root, err := conn.Search(ldap.NewSearchRequest("", ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{schema.AttrSubSchemaDN}, nil))
	require.NoError(t, err)
	require.Len(t, root.Entries, 1)
	dn := root.Entries[0].GetAttributeValue(schema.AttrSubSchemaDN)
	require.NotEmpty(t, dn)

	entry, err := conn.Search(ldap.NewSearchRequest(dn, ldap.ScopeBaseObject, ldap.NeverDerefAliases, 1, 0, false, "(objectClass=*)", []string{schema.AttrObjectClasses, schema.AttrAttributeTypes}, nil))
	require.NoError(t, err)
	require.Len(t, entry.Entries, 1)
	return entry.Entries[0].GetAttributeValues(schema.AttrObjectClasses), entry.Entries[0].GetAttributeValues(schema.AttrAttributeTypes)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// deleteTree deletes the entry, and those under it, the deepest first
func deleteTree(ctx context.Context, m *manager.Manager, dn string) error {
	parent, err := schema.NewDN(dn)
	if err != nil {
		return err
	}
	// Every page, before any is deleted, which would move the offsets
	tree := []*schema.DN{parent}
	for offset := uint64(0); ; {
		list, err := m.List(ctx, schema.ObjectListRequest{ListRequest: schema.ListRequest{OffsetLimit: schema.OffsetLimit{Offset: offset}, Attr: []string{"1.1"}}})
		if err != nil {
			return err
		}
		for _, object := range list.Body {
			if child, err := schema.NewDN(object.DN); err == nil && (*ldap.DN)(parent).AncestorOfFold((*ldap.DN)(child)) {
				tree = append(tree, child)
			}
		}
		offset += uint64(len(list.Body))
		if len(list.Body) == 0 || offset >= list.Count {
			break
		}
	}
	sort.Slice(tree, func(i, j int) bool { return len(tree[i].RDNs) > len(tree[j].RDNs) })
	for _, dn := range tree {
		if _, err := m.Delete(ctx, dn.String()); err != nil {
			return err
		}
	}
	return nil
}

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

	// The organizational units of the users and groups
	for _, dn := range []string{server.UserDN, server.GroupDN} {
		ou := strings.TrimPrefix(strings.SplitN(dn, ",", 2)[0], "ou=")
		add := ldap.NewAddRequest(dn+","+server.BaseDN, nil)
		add.Attribute("objectClass", []string{"top", "organizationalUnit"})
		add.Attribute("ou", []string{ou})
		if err := conn.Add(add); err != nil && !ldap.IsErrorWithCode(err, ldap.LDAPResultEntryAlreadyExists) {
			return c, "", fmt.Errorf("%s: creating %s: %w", server.Name, add.DN, err)
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
