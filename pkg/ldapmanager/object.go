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
	"context"
	"errors"
	"io"
	"net/url"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	ldap "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - OBJECTS

// Return the objects as a list
func (manager *Manager) List(ctx context.Context, request schema.ObjectListRequest) (*schema.ObjectList, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// Set the limit to be the minimum of user and schema limits
	limit := uint64(schema.MaxListEntries)
	if request.Limit != nil {
		limit = min(types.Value(request.Limit), limit)
	}

	// Set filter
	filter := "(objectclass=*)"
	if request.Filter != nil {
		filter = types.Value(request.Filter)
	}

	// Perform the search through paging, skipping the first N entries
	var list schema.ObjectList
	if err := manager.list(ctx, ldap.ScopeWholeSubtree, manager.dn.String(), filter, 0, func(entry *schema.Object) error {
		if list.Count >= request.Offset && list.Count < request.Offset+limit {
			list.Body = append(list.Body, entry)
		}
		list.Count = list.Count + 1
		return nil
	}, request.Attr...); err != nil {
		return nil, err
	}

	// Return success
	return &list, nil
}

// Return the objects as a list using paging, calling a function for each entry.
// When max is zero, paging is used to retrieve all entries. If max is greater than zero,
// then the maximum number of entries is returned.
func (manager *Manager) list(ctx context.Context, scope int, dn, filter string, max uint64, fn func(*schema.Object) error, attrs ...string) error {
	// Create the paging control
	var controls []ldap.Control
	paging := ldap.NewControlPaging(schema.MaxListPaging)
	if max == 0 {
		controls = []ldap.Control{paging}
	}

	// Create the search request
	req := ldap.NewSearchRequest(
		dn,
		scope,
		ldap.NeverDerefAliases,
		int(max), // Size Limit
		0,        // Time Limit
		false,    // Types Only
		filter,   // Filter
		attrs,    // Attributes
		controls, // Controls
	)

	// Perform the search through paging
	for {
		r := manager.conn.SearchAsync(ctx, req, 0)
		for r.Next() {
			entry := r.Entry()
			if entry == nil {
				continue
			}
			if err := fn(schema.NewObjectFromEntry(entry)); errors.Is(err, io.EOF) {
				break
			} else if err != nil {
				return err
			}
		}
		if err := r.Err(); err != nil {
			return ldaperr(err)
		}

		// Get response paging control, and copy the cookie over
		if resp, ok := ldap.FindControl(r.Controls(), ldap.ControlTypePaging).(*ldap.ControlPaging); !ok {
			break
		} else if len(resp.Cookie) == 0 {
			break
		} else {
			paging.SetCookie(resp.Cookie)
		}
	}

	// Return success
	return nil
}

// Get an object by DN
func (manager *Manager) Get(ctx context.Context, dn string) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Get the object
	return manager.get(ctx, ldap.ScopeBaseObject, absdn.String(), "(objectclass=*)")
}

func (manager *Manager) get(ctx context.Context, scope int, dn, filter string, attrs ...string) (*schema.Object, error) {
	var result *schema.Object

	// Search for one object
	if err := manager.list(ctx, scope, dn, filter, 1, func(entry *schema.Object) error {
		result = entry
		return io.EOF
	}, attrs...); errors.Is(err, io.EOF) {
		// Do nothing
	} else if err != nil {
		return nil, err
	}

	// Return success
	return result, nil
}

// Create an object
func (manager *Manager) Create(ctx context.Context, dn string, attr url.Values) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Create the request
	addReq := ldap.NewAddRequest(absdn.String(), []ldap.Control{})
	for key, values := range attr {
		if len(values) > 0 {
			addReq.Attribute(key, values)
		}
	}

	// Make the request
	if err := manager.conn.Add(addReq); err != nil {
		return nil, ldaperr(err)
	}

	// Return the new object
	return manager.get(ctx, ldap.ScopeBaseObject, addReq.DN, "(objectclass=*)")
}

// Delete an object by DN
func (manager *Manager) Delete(ctx context.Context, dn string) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Get the object
	object, err := manager.get(ctx, ldap.ScopeBaseObject, absdn.String(), "(objectclass=*)")
	if err != nil {
		return nil, ldaperr(err)
	}

	// Delete the object
	if err := manager.conn.Del(ldap.NewDelRequest(object.DN, []ldap.Control{})); err != nil {
		return nil, ldaperr(err)
	}

	// Return success
	return object, nil
}

// Bind a user to check if they are authenticated, returns
// httpresponse.ErrNotAuthorized if the credentials are invalid
func (manager *Manager) Bind(ctx context.Context, dn, password string) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Bind
	if err := manager.conn.Bind(absdn.String(), password); err != nil {
		return nil, ldaperr(err)
	}

	// Rebind with this user
	if err := ldapBind(manager.conn, manager.User(), manager.pass); err != nil {
		return nil, ldaperr(err)
	}

	// Return the user
	return manager.get(ctx, ldap.ScopeBaseObject, absdn.String(), "(objectclass=*)")
}

// Change a password for a user. If the new password is empty, then the password is reset
// to a new random password and returned. The old password is required for the change if
// the ldap connection is not bound to the admin user.
func (manager *Manager) ChangePassword(ctx context.Context, dn, old string, new *string) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// New password is required
	if new == nil {
		return nil, httpresponse.ErrBadRequest.With("New password parameter is required")
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Modify the password
	if result, err := manager.conn.PasswordModify(ldap.NewPasswordModifyRequest(absdn.String(), old, types.PtrString(new))); err != nil {
		return nil, ldaperr(err)
	} else if new != nil {
		*new = result.GeneratedPassword
	}

	// Return the user
	return manager.get(ctx, ldap.ScopeBaseObject, absdn.String(), "(objectclass=*)")
}

// Update attributes for an object. It will replace the attributes where the values is not empty,
// and delete the attributes where the values is empty. The object is returned after the update.
func (manager *Manager) Update(ctx context.Context, dn string, attr url.Values) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Create the request
	modifyReq := ldap.NewModifyRequest(absdn.String(), []ldap.Control{})
	for key, values := range attr {
		modifyReq.Replace(key, values)
	}

	// Make the request
	if err := manager.conn.Modify(modifyReq); err != nil {
		return nil, ldaperr(err)
	}

	// Return the new object
	return manager.get(ctx, ldap.ScopeBaseObject, absdn.String(), "(objectclass=*)")
}
