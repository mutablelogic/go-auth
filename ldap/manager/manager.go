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

// Package manager connects to an LDAP directory, and keeps the connection,
// binding as the manager's user, and reconnecting when it's lost
package manager

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// Manager keeps a connection to an LDAP directory
type Manager struct {
	mu         sync.Mutex
	url        *url.URL
	tls        *tls.Config
	user, pass string
	dn         *schema.DN
	conn       *ldap.Conn
	lost       chan struct{}
	users      *schema.Group
	groups     *schema.Group
	tracer     trace.Tracer
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// New returns a manager of the directory at the URL, ldap or ldaps, whose
// user and password are the URL's, unless they're options, under the base
// DN. It doesn't connect until Connect, or Run, is called.
func New(opt ...Opt) (*Manager, error) {
	self := new(Manager)
	self.lost = make(chan struct{}, 1)

	// Apply options
	o, err := applyOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Set the url for the connection, which is a copy, as its user is
	// removed
	if o.url == nil {
		return nil, httpresponse.ErrBadRequest.With("missing url parameter")
	}
	u := *o.url
	self.url = &u

	// Check the scheme, and set the default port
	switch self.url.Scheme {
	case schema.MethodPlain:
		if self.url.Port() == "" {
			self.url.Host = fmt.Sprintf("%s:%d", self.url.Hostname(), schema.PortPlain)
		}
	case schema.MethodSecure:
		if self.url.Port() == "" {
			self.url.Host = fmt.Sprintf("%s:%d", self.url.Hostname(), schema.PortSecure)
		}
		self.tls = &tls.Config{
			InsecureSkipVerify: o.skipverify,
		}
	default:
		return nil, httpresponse.ErrBadRequest.Withf("scheme not supported: %q", self.url.Scheme)
	}
	if self.url.Hostname() == "" {
		return nil, httpresponse.ErrBadRequest.With("missing host in url")
	}

	// Extract the user
	if o.user != "" {
		self.user = o.user
	} else if self.url.User == nil || self.url.User.Username() == "" {
		return nil, httpresponse.ErrBadRequest.With("missing user parameter")
	} else {
		self.user = self.url.User.Username()
	}

	// Extract the password
	if o.pass != "" {
		self.pass = o.pass
	} else if self.url.User != nil {
		if password, ok := self.url.User.Password(); ok {
			self.pass = password
		}
	}

	// Blank out the user and password in the URL
	self.url.User = nil

	// Set the Distinguished Name
	if o.dn == nil {
		return nil, httpresponse.ErrBadRequest.With("missing dn parameter")
	}
	self.dn = o.dn

	// Set the schemas for users, groups
	self.users = o.users
	self.groups = o.groups
	self.tracer = o.tracer

	// Return success
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Port returns the port of the directory
func (manager *Manager) Port() uint {
	port, err := strconv.ParseUint(manager.url.Port(), 10, 16)
	if err != nil {
		return 0
	}
	return uint(port)
}

// Host returns the host of the directory
func (manager *Manager) Host() string {
	return manager.url.Hostname()
}

// User returns the DN the manager binds as: a name, such as admin, is the
// common name under the base DN, and anything else is a DN
func (manager *Manager) User() string {
	if types.IsIdentifier(manager.user) {
		return fmt.Sprint("cn=", manager.user, ",", manager.dn)
	}
	return manager.user
}

// Connect connects to the directory, and binds, or, when it's connected,
// checks the connection, which is closed when it's lost, so the next call
// connects again
func (manager *Manager) Connect(ctx context.Context) (err error) {
	_, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Connect", manager.serverAttrs()...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.conn == nil {
		conn, err := ldapConnect(ctx, manager.Host(), manager.Port(), manager.tls)
		if err != nil {
			return err
		}
		if err := whileOpen(ctx, conn, func() error { return ldapBind(conn, manager.User(), manager.pass) }); err != nil {
			return errors.Join(ldaperr(err), ldapDisconnect(conn))
		}
		manager.conn = conn
	} else if err = whileOpen(ctx, manager.conn, func() error {
		_, err := manager.conn.WhoAmI([]ldap.Control{})
		return err
	}); err != nil {
		var conn *ldap.Conn
		conn, manager.conn = manager.conn, nil
		return errors.Join(err, ldapDisconnect(conn))
	}

	// Return success
	return nil
}

// write calls the function with the manager's connection, which is closed
// when the context is cancelled first, so a directory which doesn't answer
// can't hold the lock. Then it's forgotten, and Run reconnects.
func (manager *Manager) write(ctx context.Context, fn func(*ldap.Conn) error) error {
	if err := manager.connected(); err != nil {
		return err
	}
	conn := manager.conn
	err := whileOpen(ctx, conn, func() error { return fn(conn) })
	if conn.IsClosing() {
		manager.forget()
	}
	return err
}

// forget forgets the manager's connection, which is closed, and wakes Run,
// which reconnects
func (manager *Manager) forget() {
	manager.conn = nil
	select {
	case manager.lost <- struct{}{}:
	default:
	}
}

// Disconnect closes the connection to the directory, when it's connected
func (manager *Manager) Disconnect(ctx context.Context) (err error) {
	_, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Disconnect", manager.serverAttrs()...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.conn != nil {
		err = ldapDisconnect(manager.conn)
		manager.conn = nil
	}
	return err
}

// WhoAmI returns the identity the manager is bound as
func (manager *Manager) WhoAmI(ctx context.Context) (_ string, err error) {
	_, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.WhoAmI", manager.serverAttrs()...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()

	if manager.conn == nil {
		return "", httpresponse.ErrGatewayError.With("Not connected")
	}
	whoami, err := manager.conn.WhoAmI([]ldap.Control{})
	if err != nil {
		return "", ldaperr(err)
	}
	return whoami.AuthzID, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// serverAttrs are a span's attributes of the directory
func (manager *Manager) serverAttrs() []attribute.KeyValue {
	return []attribute.KeyValue{
		attribute.String("server.address", manager.Host()),
		attribute.Int("server.port", int(manager.Port())),
	}
}

// ldapConnect connects to the directory, with TLS when there's a
// configuration, until the context is cancelled. Its requests time out.
func ldapConnect(ctx context.Context, host string, port uint, config *tls.Config) (*ldap.Conn, error) {
	addr := net.JoinHostPort(host, strconv.FormatUint(uint64(port), 10))
	dialer := &net.Dialer{Timeout: schema.RequestTimeout}

	var conn net.Conn
	var err error
	if config != nil {
		conn, err = (&tls.Dialer{NetDialer: dialer, Config: config}).DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return nil, ldap.NewError(ldap.ErrorNetwork, err)
	}

	result := ldap.NewConn(conn, config != nil)
	result.Start()
	result.SetTimeout(schema.RequestTimeout)
	return result, nil
}

// whileOpen calls the function, and closes the connection if the context is
// cancelled first, so a directory which doesn't answer can't block a caller
// which holds the lock. It returns the context's error, when it was.
func whileOpen(ctx context.Context, conn *ldap.Conn, fn func() error) error {
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	err := fn()
	if !stop() {
		return errors.Join(ctx.Err(), err)
	}
	return err
}

// ldapDisconnect closes the connection, which may have been closed already
func ldapDisconnect(conn *ldap.Conn) error {
	if err := conn.Close(); err != nil && !isIgnorableLDAPDisconnectError(err) {
		return err
	}
	return nil
}

// ldapBind binds with the user and password, or without a password, when
// there's none
func ldapBind(conn *ldap.Conn, user, password string) error {
	if password == "" {
		return conn.UnauthenticatedBind(user)
	}
	return conn.Bind(user, password)
}

// ldapErrorCode returns the LDAP result code of an error, or zero
func ldapErrorCode(err error) uint16 {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return uint16(ldapErr.ResultCode)
	}
	return 0
}

// isIgnorableLDAPDisconnectError is true when the connection was closed
// already
func isIgnorableLDAPDisconnectError(err error) bool {
	if err == nil {
		return true
	}
	if ldapErrorCode(err) == ldap.ErrorNetwork {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection closed")
}

// ldaperr translates an LDAP error into an HTTP error
func ldaperr(err error) error {
	if err == nil {
		return nil
	}
	// A cancelled request is the caller's, not the directory's, error
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	code := ldapErrorCode(err)
	if code == 0 {
		return err
	}
	switch code {
	case ldap.LDAPResultInvalidCredentials:
		return httpresponse.ErrNotAuthorized.With("Invalid credentials")
	case ldap.ErrorFilterCompile, ldap.ErrorFilterDecompile, ldap.LDAPResultFilterError, ldap.LDAPResultParamError, ldap.LDAPResultInvalidAttributeSyntax, ldap.LDAPResultObjectClassViolation, ldap.LDAPResultNamingViolation, ldap.LDAPResultUnwillingToPerform, ldap.LDAPResultUndefinedAttributeType, ldap.LDAPResultNotAllowedOnRDN:
		return httpresponse.ErrBadRequest.With(err.Error())
	case ldap.LDAPResultInsufficientAccessRights:
		return httpresponse.ErrForbidden.With(err.Error())
	case ldap.LDAPResultNoSuchObject:
		return httpresponse.ErrNotFound.With("No such object")
	case ldap.LDAPResultEntryAlreadyExists:
		return httpresponse.ErrConflict.With(err.Error())
	case ldap.LDAPResultNoSuchAttribute:
		return httpresponse.ErrNotFound.With(err.Error())
	case ldap.LDAPResultConstraintViolation, ldap.LDAPResultNotAllowedOnNonLeaf:
		return httpresponse.ErrConflict.With(err.Error())
	default:
		return httpresponse.ErrInternalError.With(err)
	}
}

// absdn returns a DN under the base DN: one which is the base DN, or under
// it, in any case, is kept, and any other is put under it
func (manager *Manager) absdn(dn string) (*schema.DN, error) {
	rdn, err := schema.NewDN(dn)
	if err != nil {
		return nil, httpresponse.ErrBadRequest.Withf("Invalid DN: %v", err.Error())
	}
	base := (*ldap.DN)(manager.dn)
	if base.EqualFold((*ldap.DN)(rdn)) || base.AncestorOfFold((*ldap.DN)(rdn)) {
		return rdn, nil
	}
	return rdn.Join(manager.dn), nil
}
