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
	"strings"

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
	attrs, err := (schema.ObjectPutRequest{Attrs: attr}).ValidateCreate()
	if err != nil {
		return nil, err
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}

	// Create the request
	addReq := ldap.NewAddRequest(absdn.String(), []ldap.Control{})
	for key, values := range attrs {
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
// to a new random password and returned. The old password may be omitted when the
// directory permits administrative password resets.
func (manager *Manager) ChangePassword(ctx context.Context, dn, old string, new *string) (*schema.Object, *string, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, nil, httpresponse.ErrGatewayError.With("Not connected")
	}
	old = strings.TrimSpace(old)

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, nil, err
	}
	requestedNew := ""
	if new != nil {
		requestedNew = strings.TrimSpace(*new)
	}

	// Modify the password
	var generated *string
	if result, err := manager.conn.PasswordModify(ldap.NewPasswordModifyRequest(absdn.String(), old, requestedNew)); err != nil {
		return nil, nil, ldaperr(err)
	} else if requestedNew == "" && strings.TrimSpace(result.GeneratedPassword) != "" {
		generated = types.Ptr(result.GeneratedPassword)
	}

	// Return the user
	object, err := manager.get(ctx, ldap.ScopeBaseObject, absdn.String(), "(objectclass=*)")
	if err != nil {
		return nil, nil, err
	}
	return object, generated, nil
}

// Update attributes for an object. It will replace the attributes where the values is not empty,
// and delete the attributes where the values is empty. If the request changes an RDN attribute,
// the entry is renamed first and then modified. The object is returned after the update.
func (manager *Manager) Update(ctx context.Context, dn string, attr url.Values) (*schema.Object, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}
	attrs, err := (schema.ObjectPutRequest{Attrs: attr}).ValidateUpdate()
	if err != nil {
		return nil, err
	}

	// Make absolute DN
	absdn, err := manager.absdn(dn, manager.dn)
	if err != nil {
		return nil, err
	}
	currentDN, targetDN, newRDN, rename, err := updateTargetDN(absdn, attrs)
	if err != nil {
		return nil, err
	}
	if rename {
		if err := manager.conn.ModifyDN(ldap.NewModifyDNRequest(currentDN, newRDN, true, "")); err != nil {
			return nil, ldaperr(err)
		}
	}

	// Create the request
	modifyReq := ldap.NewModifyRequest(targetDN, []ldap.Control{})
	for key, values := range attrs {
		if len(values) == 0 {
			modifyReq.Delete(key, nil)
		} else {
			modifyReq.Replace(key, values)
		}
	}

	// Make the request
	if err := manager.conn.Modify(modifyReq); err != nil {
		return nil, ldaperr(err)
	}

	// Return the new object
	return manager.get(ctx, ldap.ScopeBaseObject, targetDN, "(objectclass=*)")
}

func updateTargetDN(dn *schema.DN, attrs url.Values) (string, string, string, bool, error) {
	if dn == nil || len(dn.RDNs) == 0 || dn.RDNs[0] == nil || len(dn.RDNs[0].Attributes) == 0 {
		return "", "", "", false, httpresponse.ErrBadRequest.With("dn is required")
	}

	currentDN := dn.String()
	currentRDN := dn.RDNs[0]
	updatedRDN := &ldap.RelativeDN{Attributes: make([]*ldap.AttributeTypeAndValue, 0, len(currentRDN.Attributes))}
	rename := false

	for _, attribute := range currentRDN.Attributes {
		if attribute == nil {
			continue
		}
		value := attribute.Value
		if values, ok := updateAttributeValues(attrs, attribute.Type); ok {
			if len(values) == 0 {
				return "", "", "", false, httpresponse.ErrBadRequest.Withf("naming attribute %q cannot be deleted; use rename", attribute.Type)
			}
			value = values[0]
		}
		updatedRDN.Attributes = append(updatedRDN.Attributes, &ldap.AttributeTypeAndValue{
			Type:  attribute.Type,
			Value: value,
		})
		if value != attribute.Value {
			rename = true
		}
	}

	if !rename {
		return currentDN, currentDN, "", false, nil
	}

	newRDN := updatedRDN.String()
	if len(dn.RDNs) == 1 {
		return currentDN, newRDN, newRDN, true, nil
	}
	parent := (&schema.DN{RDNs: append([]*ldap.RelativeDN(nil), dn.RDNs[1:]...)}).String()
	return currentDN, newRDN + "," + parent, newRDN, true, nil
}

func updateAttributeValues(attrs url.Values, name string) ([]string, bool) {
	for key, values := range attrs {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}
