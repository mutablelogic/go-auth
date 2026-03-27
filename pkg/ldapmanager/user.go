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
	"net/url"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - USERS AND GROUPS

// Return all users
func (manager *Manager) ListUsers(ctx context.Context, request schema.ObjectListRequest) ([]*schema.ObjectList, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("ListUsers not implemented")
}

// Get a user
func (manager *Manager) GetUser(ctx context.Context, dn string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("GetUser not implemented")
}

// Create a user
func (manager *Manager) CreateUser(ctx context.Context, user string, attrs url.Values) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("CreateUser not implemented")
}

// Delete a user
func (manager *Manager) DeleteUser(ctx context.Context, dn string) (*schema.Object, error) {
	// TODO
	return nil, httpresponse.ErrNotImplemented.With("DeleteUser not implemented")
}

/*

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
