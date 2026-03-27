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
	"crypto/tls"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	ldap "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// LDAP manager
type Manager struct {
	sync.Mutex
	url        *url.URL
	tls        *tls.Config
	user, pass string
	dn         *schema.DN
	conn       *ldap.Conn
	users      *schema.Group
	groups     *schema.Group
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

	// Return success
	return self, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Return the port for the LDAP connection
func (ldap *Manager) Port() int {
	port, err := strconv.ParseUint(ldap.url.Port(), 10, 32)
	if err != nil {
		return 0
	} else {
		return int(port)
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

// Connect to the LDAP server, or ping the server if already connected
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
func ldapConnect(host string, port int, tls *tls.Config) (*ldap.Conn, error) {
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
	return conn.Close()
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

/*
///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - USERS AND GROUPS

// Return all users
func (manager *Manager) ListUsers(ctx context.Context, request schema.ObjectListRequest) ([]*schema.ObjectList, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("ListUsers not implemented")
}

// Return all groups
func (manager *Manager) ListGroups(ctx context.Context, request schema.ObjectListRequest) ([]*schema.ObjectList, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("ListGroups not implemented")
}

// Get a user
func (manager *Manager) GetUser(ctx context.Context, dn string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("GetUser not implemented")
}

// Get a group
func (manager *Manager) GetGroup(ctx context.Context, dn string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("GetGroup not implemented")
}

// Create a user
func (manager *Manager) CreateUser(ctx context.Context, user string, attrs url.Values) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("CreateUser not implemented")
}

// Create a group
func (manager *Manager) CreateGroup(ctx context.Context, group string, attrs url.Values) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("CreateGroup not implemented")
}

// Delete a user
func (manager *Manager) DeleteUser(ctx context.Context, dn string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("DeleteUser not implemented")
}

// Delete a group
func (manager *Manager) DeleteGroup(ctx context.Context, dn string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("DeleteGroup not implemented")
}

// Add a user to a group, and return the group
func (manager *Manager) AddGroupUser(ctx context.Context, dn, user string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("DeleteGroup not implemented")
}

// Remove a user from a group, and return the group
func (manager *Manager) RemoveGroupUser(ctx context.Context, dn, user string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("DeleteGroup not implemented")
}

/*
// Return all groups
func (ldap *ldap) GetGroups() ([]*schema.Object, error) {
	return ldap.Get(ldap.schema.GroupObjectClass[0])
}

// Create a group with the given attributes
func (ldap *ldap) CreateGroup(group string, attrs ...schema.Attr) (*schema.Object, error) {
	ldap.Lock()
	defer ldap.Unlock()

	// Check connection
	if ldap.conn == nil {
		return nil, ErrOutOfOrder.With("Not connected")
	}

	// Create group
	o, err := ldap.schema.NewGroup(ldap.dn, group, attrs...)
	if err != nil {
		return nil, err
	}

	// If the gid is not set, then set it to the next available gid
	var nextGid int
	gid, err := ldap.SearchOne("(&(objectclass=device)(cn=lastgid))")
	if err != nil {
		return nil, err
	} else if gid == nil {
		return nil, ErrNotImplemented.With("lastgid not found")
	} else if gid_, err := strconv.ParseInt(gid.Get("serialNumber"), 10, 32); err != nil {
		return nil, ErrNotImplemented.With("lastgid not found")
	} else {
		nextGid = int(gid_) + 1
		if err := schema.OptGroupId(int(gid_))(o); err != nil {
			return nil, err
		}
	}

	// Create the request
	addReq := goldap.NewAddRequest(o.DN, []goldap.Control{})
	for name, values := range o.Values {
		addReq.Attribute(name, values)
	}

	// Request -> Response
	if err := ldap.conn.Add(addReq); err != nil {
		return nil, err
	}

	// Increment the gid
	if gid != nil && nextGid > 0 {
		modify := goldap.NewModifyRequest(gid.DN, []goldap.Control{})
		modify.Replace("serialNumber", []string{fmt.Sprint(nextGid)})
		if err := ldap.conn.Modify(modify); err != nil {
			return nil, err
		}
	}

	// TODO: Retrieve the group

	// Return success
	return o, nil
}

// Add a user to a group
func (ldap *ldap) AddGroupUser(user, group *schema.Object) error {
	// Use uniqueMember for groupOfUniqueNames,
	// use memberUid for posixGroup
	// use member for groupOfNames or if not posix
	return ErrNotImplemented
}

// Remove a user from a group
func (ldap *ldap) RemoveGroupUser(user, group *schema.Object) error {
	// Use uniqueMember for groupOfUniqueNames,
	// use memberUid for posixGroup
	// use member for groupOfNames or if not posix
	return ErrNotImplemented
}

// Create a user in a specific group with the given attributes
func (ldap *ldap) CreateUser(name string, attrs ...schema.Attr) (*schema.Object, error) {
	ldap.Lock()
	defer ldap.Unlock()

	// Check connection
	if ldap.conn == nil {
		return nil, ErrOutOfOrder.With("Not connected")
	}

	// Create user object
	o, err := ldap.schema.NewUser(ldap.dn, name, attrs...)
	if err != nil {
		return nil, err
	}

	// If the uid is not set, then set it to the next available uid
	var nextId int
	uid, err := ldap.SearchOne("(&(objectclass=device)(cn=lastuid))")
	if err != nil {
		return nil, err
	} else if uid == nil {
		return nil, ErrNotImplemented.With("lastuid not found")
	} else if uid_, err := strconv.ParseInt(uid.Get("serialNumber"), 10, 32); err != nil {
		return nil, ErrNotImplemented.With("lastuid not found")
	} else {
		nextId = int(uid_) + 1
		if err := schema.OptUserId(int(uid_))(o); err != nil {
			return nil, err
		}
	}

	// Create the request
	addReq := goldap.NewAddRequest(o.DN, []goldap.Control{})
	for name, values := range o.Values {
		addReq.Attribute(name, values)
	}

	// Request -> Response
	if err := ldap.conn.Add(addReq); err != nil {
		return nil, err
	}

	// Increment the uid
	if uid != nil && nextId > 0 {
		modify := goldap.NewModifyRequest(uid.DN, []goldap.Control{})
		modify.Replace("serialNumber", []string{fmt.Sprint(nextId)})
		if err := ldap.conn.Modify(modify); err != nil {
			return nil, err
		}
	}

	// TODO: Add the user to a group

	// Return success
	return o, nil
}
*/
