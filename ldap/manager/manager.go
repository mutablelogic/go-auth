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

package ldap

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"unicode/utf16"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// LDAP manager
type Manager struct {
	sync.Mutex
	url           *url.URL
	tls           *tls.Config
	skipverify    bool
	user, pass    string
	dn            *schema.DN
	conn          *ldap.Conn
	users         *schema.Group
	groups        *schema.Group
	discoveryOnce sync.Once
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func New(opt ...Opt) (*Manager, error) {
	self := new(Manager)

	// Apply options
	o, err := applyOpts(opt...)
	if err != nil {
		return nil, err
	}

	// Set the url for the connection
	if o.url == nil {
		return nil, httpresponse.ErrBadRequest.With("missing url parameter")
	} else {
		self.url = o.url
	}

	// Check the scheme
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
		return nil, fmt.Errorf("scheme not supported: %q", self.url.Scheme)
	}

	// Extract the user
	if o.user != "" {
		self.user = o.user
	} else if self.url.User == nil {
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
	} else {
		self.dn = o.dn
	}

	// Set the schemas for users, groups
	self.users = o.users
	self.groups = o.groups

	// Set SSL verification
	self.skipverify = o.skipverify

	// Return success
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Return the port for the LDAP connection
func (ldap *Manager) Port() uint {
	port, err := strconv.ParseUint(ldap.url.Port(), 10, 32)
	if err != nil {
		return 0
	} else {
		return uint(port)
	}
}

// Return the host for the LDAP connection
func (ldap *Manager) Host() string {
	return ldap.url.Hostname()
}

// Return the user for the LDAP connection
func (ldap *Manager) User() string {
	if types.IsIdentifier(ldap.user) {
		// If it's an identifier, then append the DN
		return fmt.Sprint("cn=", ldap.user, ",", ldap.dn)
	} else {
		// Assume it's a DN
		return ldap.user
	}
}

// Connect to the LDAP server, or ping the server if already connected.
func (manager *Manager) Connect() error {
	manager.Lock()
	defer manager.Unlock()

	if manager.conn == nil {
		if conn, err := ldapConnect(manager.Host(), manager.Port(), manager.tls); err != nil {
			return err
		} else if err := ldapBind(conn, manager.User(), manager.pass); err != nil {
			return ldaperr(err)
		} else {
			manager.conn = conn
		}
	} else if _, err := manager.conn.WhoAmI([]ldap.Control{}); err != nil {
		// TODO: ldap.ErrorNetwork, ldap.LDAPResultBusy, ldap.LDAPResultUnavailable:
		// would indicate that the connection is no longer valid
		var conn *ldap.Conn
		conn, manager.conn = manager.conn, nil
		return errors.Join(err, ldapDisconnect(conn))
	}

	// Return success
	return nil
}

// Disconnect from the LDAP server
func (ldap *Manager) Disconnect() error {
	ldap.Lock()
	defer ldap.Unlock()

	// Disconnect from LDAP connection
	var result error
	if ldap.conn != nil {
		if err := ldapDisconnect(ldap.conn); err != nil {
			result = errors.Join(result, err)
		}
		ldap.conn = nil
	}

	// Return any errors
	return result
}

// Return the user who is currently authenticated
func (manager *Manager) WhoAmI() (string, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return "", httpresponse.ErrGatewayError.With("Not connected")
	}

	// Ping
	if whoami, err := manager.conn.WhoAmI([]ldap.Control{}); err != nil {
		return "", ldaperr(err)
	} else {
		return whoami.AuthzID, nil
	}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// Connect to the LDAP server
func ldapConnect(host string, port uint, tls *tls.Config) (*ldap.Conn, error) {
	var url string
	if tls == nil {
		url = fmt.Sprintf("%s://%s:%d", schema.MethodPlain, host, port)
	} else {
		url = fmt.Sprintf("%s://%s:%d", schema.MethodSecure, host, port)
	}
	return ldap.DialURL(url, ldap.DialWithTLSConfig(tls))
}

// Disconnect from the LDAP server
func ldapDisconnect(conn *ldap.Conn) error {
	if err := conn.Close(); err != nil && !isIgnorableLDAPDisconnectError(err) {
		return err
	}
	return nil
}

// Bind to the LDAP server with a user and password
func ldapBind(conn *ldap.Conn, user, password string) error {
	if password == "" {
		return conn.UnauthenticatedBind(user)
	} else {
		return conn.Bind(user, password)
	}
}

// Return the LDAP error code
func ldapErrorCode(err error) uint16 {
	var ldapErr *ldap.Error
	if errors.As(err, &ldapErr) {
		return uint16(ldapErr.ResultCode)
	}
	return 0
}

func (manager *Manager) passwordEndpoint() (*url.URL, *tls.Config) {
	if manager.url.Scheme == schema.MethodSecure {
		return manager.url, manager.tls
	}
	clone := *manager.url
	clone.Scheme = schema.MethodSecure
	clone.Host = fmt.Sprintf("%s:%d", manager.url.Hostname(), schema.PortSecure)
	clone.User = nil
	return &clone, &tls.Config{InsecureSkipVerify: manager.skipverify}
}

func (manager *Manager) openPasswordConn() (*ldap.Conn, error) {
	endpoint, tlsConfig := manager.passwordEndpoint()
	port, err := strconv.ParseUint(endpoint.Port(), 10, 16)
	if err != nil {
		return nil, err
	}
	return ldapConnect(endpoint.Hostname(), uint(port), tlsConfig)
}

func (manager *Manager) bindPasswordConn() (*ldap.Conn, error) {
	conn, err := manager.openPasswordConn()
	if err != nil {
		return nil, err
	}
	if err := ldapBind(conn, manager.User(), manager.pass); err != nil {
		_ = ldapDisconnect(conn)
		return nil, ldaperr(err)
	}
	return conn, nil
}

func activeDirectoryPasswordSchema(classes []string) bool {
	return containsFold(classes, "user")
}

func activeDirectoryPasswordValue(password string) string {
	encoded := utf16.Encode([]rune("\"" + password + "\""))
	buf := make([]byte, len(encoded)*2)
	for i, value := range encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], value)
	}
	return string(buf)
}

func randomPassword() (string, error) {
	buf := make([]byte, 18)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

func (manager *Manager) setActiveDirectoryPassword(dn, old, password string) error {
	old = strings.TrimSpace(old)
	var (
		conn *ldap.Conn
		err  error
	)
	if old == "" {
		conn, err = manager.bindPasswordConn()
	} else {
		conn, err = manager.openPasswordConn()
		if err == nil {
			err = ldapBind(conn, dn, old)
			if err != nil {
				_ = ldapDisconnect(conn)
				return ldaperr(err)
			}
		}
	}
	if err != nil {
		return err
	}
	defer ldapDisconnect(conn)

	req := ldap.NewModifyRequest(dn, []ldap.Control{})
	if old == "" {
		// Administrative reset: replace unicodePwd with the new quoted UTF-16LE value.
		req.Replace("unicodePwd", []string{activeDirectoryPasswordValue(password)})
	} else {
		// User-initiated change: delete the old value and add the new one in the
		// same modify request, per MS-ADTS password change semantics.
		req.Delete("unicodePwd", []string{activeDirectoryPasswordValue(old)})
		req.Add("unicodePwd", []string{activeDirectoryPasswordValue(password)})
	}
	if err := conn.Modify(req); err != nil {
		return ldaperr(err)
	}
	return nil
}

func isIgnorableLDAPDisconnectError(err error) bool {
	if err == nil {
		return true
	}
	if ldapErrorCode(err) == ldap.ErrorNetwork {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "connection closed")
}

// Translate LDAP error to HTTP error
func ldaperr(err error) error {
	if err == nil {
		return nil
	}
	code := ldapErrorCode(err)
	if code == 0 {
		return err
	}
	switch code {
	case ldap.LDAPResultInvalidCredentials:
		return httpresponse.ErrNotAuthorized.With("Invalid credentials")
	case ldap.ErrorFilterCompile, ldap.ErrorFilterDecompile, ldap.LDAPResultFilterError, ldap.LDAPResultParamError, ldap.LDAPResultInvalidAttributeSyntax, ldap.LDAPResultObjectClassViolation, ldap.LDAPResultNamingViolation, ldap.LDAPResultUnwillingToPerform:
		return httpresponse.ErrBadRequest.With(err.Error())
	case ldap.LDAPResultNoSuchObject:
		return httpresponse.ErrNotFound.With("No such object")
	case ldap.LDAPResultEntryAlreadyExists:
		return httpresponse.ErrConflict.With(err.Error())
	case ldap.LDAPResultNoSuchAttribute:
		return httpresponse.ErrNotFound.With(err.Error())
	case ldap.LDAPResultConstraintViolation:
		return httpresponse.ErrConflict.With(err.Error())
	default:
		return httpresponse.ErrInternalError.With(err)
	}
}

// Make the DN absolute
func (manager *Manager) absdn(dn string, base *schema.DN) (*schema.DN, error) {
	rdn, err := schema.NewDN(dn)
	if err != nil {
		return nil, httpresponse.ErrBadRequest.Withf("Invalid DN: %v", err.Error())
	}
	if !manager.dn.AncestorOf(rdn) {
		return rdn.Join(manager.dn), nil
	}
	return rdn, nil
}
