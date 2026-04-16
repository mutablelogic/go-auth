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
	"net/url"
	"strconv"

	// Packages
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	ldap "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - USERS AND GROUPS

// Return all users
func (manager *Manager) ListUsers(ctx context.Context, request schema.ObjectListRequest) (*schema.ObjectList, error) {
	var result *schema.ObjectList
	return result, manager.withUsers("", func(searchBase *schema.DN) error {
		filter := "(objectClass=*)"
		if request.Filter != nil {
			filter = types.Value(request.Filter)
		}

		limit := uint64(schema.MaxListEntries)
		if request.Limit != nil {
			limit = min(types.Value(request.Limit), limit)
		}

		var list schema.ObjectList
		if err := manager.list(ctx, ldap.ScopeSingleLevel, searchBase.String(), filter, 0, func(entry *schema.Object) error {
			if list.Count >= request.Offset && list.Count < request.Offset+limit {
				list.Body = append(list.Body, entry)
			}
			list.Count++
			return nil
		}, request.Attr...); err != nil {
			return err
		}
		result = &list
		return nil
	})
}

// Get a user
func (manager *Manager) GetUser(ctx context.Context, cn string) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withUsers(cn, func(dn *schema.DN) error {
		var err error
		result, err = manager.get(ctx, ldap.ScopeBaseObject, dn.String(), "(objectClass=*)")
		return err
	})
}

// Create a user. When allocateGID is true and gidNumber is not supplied for a
// posixAccount entry, gidNumber is set to the effective uidNumber.
func (manager *Manager) CreateUser(ctx context.Context, user string, attrs url.Values, allocateGID bool) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withUsers(user, func(userDN *schema.DN) error {
		searchReq := ldap.NewSearchRequest(
			userDN.String(),
			ldap.ScopeBaseObject,
			ldap.NeverDerefAliases,
			1,
			0,
			false,
			"(objectClass=*)",
			[]string{"1.1"},
			nil,
		)
		if _, err := manager.conn.Search(searchReq); err == nil {
			return httpresponse.ErrConflict.With("user already exists")
		} else if ldapErrorCode(err) != ldap.LDAPResultNoSuchObject {
			return ldaperr(err)
		}

		if attrs == nil {
			attrs = make(url.Values)
		}
		classes := manager.users.ObjectClass
		if len(classes) == 0 {
			classes = schema.DefaultUserObjectClasses
		}
		existing := attrValues(attrs, "objectClass")
		if !containsFold(existing, "top") {
			existing = append([]string{"top"}, existing...)
		}
		for _, class := range classes {
			if !containsFold(existing, class) {
				existing = append(existing, class)
			}
		}
		attrSet(attrs, "objectClass", existing)

		if allocateGID {
			if !containsFold(classes, "posixAccount") {
				return httpresponse.ErrBadRequest.With("allocate_gid requires posixAccount user schema")
			}
			if attrHas(attrs, "gidNumber") {
				return httpresponse.ErrBadRequest.With("allocate_gid cannot be used when gidNumber is provided")
			}
		}

		rdnAttr := userNamingAttribute(classes)
		attrSet(attrs, rdnAttr, []string{user})

		if containsFold(classes, "posixAccount") && !attrHas(attrs, "uidNumber") {
			uid, err := manager.nextUID(ctx)
			if err != nil {
				return err
			}
			attrSet(attrs, "uidNumber", []string{strconv.Itoa(uid)})
		}
		if allocateGID {
			if uid := attrValues(attrs, "uidNumber"); len(uid) > 0 {
				attrSet(attrs, "gidNumber", []string{uid[0]})
			}
		}

		password := attrFirst(attrs, "unicodePwd")
		if password == "" {
			password = attrFirst(attrs, "userPassword")
		}
		usesActiveDirectoryPasswords := activeDirectoryPasswordSchema(classes)
		if usesActiveDirectoryPasswords {
			// MS-ADTS password writes use unicodePwd over a protected connection,
			// so seed the entry first and then apply the password in a follow-up modify.
			attrDelete(attrs, "userPassword")
			attrDelete(attrs, "unicodePwd")
			if !attrHas(attrs, "sAMAccountName") {
				attrSet(attrs, "sAMAccountName", []string{user})
			}
			if !attrHas(attrs, "userAccountControl") {
				attrSet(attrs, "userAccountControl", []string{"512"})
			}
		}

		addReq := ldap.NewAddRequest(userDN.String(), []ldap.Control{})
		for key, values := range attrs {
			if len(values) > 0 {
				addReq.Attribute(key, values)
			}
		}
		if err := manager.conn.Add(addReq); err != nil {
			return ldaperr(err)
		}
		if usesActiveDirectoryPasswords && password != "" {
			if err := manager.setActiveDirectoryPassword(addReq.DN, "", password); err != nil {
				if delErr := manager.conn.Del(ldap.NewDelRequest(addReq.DN, []ldap.Control{})); delErr != nil {
					return errors.Join(err, ldaperr(delErr))
				}
				return err
			}
		}
		var err error
		result, err = manager.get(ctx, ldap.ScopeBaseObject, addReq.DN, "(objectClass=*)")
		return err
	})
}

// Update attributes for a user. It will replace the attributes where the
// values are not empty, and delete the attributes where the values are empty.
// If the request changes the naming attribute, the entry is renamed first and
// then modified. The updated user is returned.
func (manager *Manager) UpdateUser(ctx context.Context, cn string, attrs url.Values) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withUsers(cn, func(userDN *schema.DN) error {
		attrs, err := (schema.ObjectPutRequest{Attrs: attrs}).ValidateUpdate()
		if err != nil {
			return err
		}

		currentDN, targetDN, newRDN, rename, err := updateTargetDN(userDN, attrs)
		if err != nil {
			return err
		}
		if rename {
			if err := manager.conn.ModifyDN(ldap.NewModifyDNRequest(currentDN, newRDN, true, "")); err != nil {
				return ldaperr(err)
			}
		}

		modifyReq, hasChanges := newModifyRequest(targetDN, attrs, userDN, rename)
		if hasChanges {
			if err := manager.conn.Modify(modifyReq); err != nil {
				return ldaperr(err)
			}
		}

		result, err = manager.get(ctx, ldap.ScopeBaseObject, targetDN, "(objectClass=*)")
		return err
	})
}

// Delete a user
func (manager *Manager) DeleteUser(ctx context.Context, cn string) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withUsers(cn, func(dn *schema.DN) error {
		object, err := manager.get(ctx, ldap.ScopeBaseObject, dn.String(), "(objectClass=*)")
		if err != nil {
			return ldaperr(err)
		}
		if err := manager.conn.Del(ldap.NewDelRequest(object.DN, []ldap.Control{})); err != nil {
			return ldaperr(err)
		}
		result = object
		return nil
	})
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - USERS

// withUsers acquires the manager lock, validates that the user schema and
// connection are ready, then calls fn with the lock held. If name is non-empty
// the resolved DN is <rdnAttr>=<name>,<userBase>; otherwise it is the user base DN.
func (manager *Manager) withUsers(name string, fn func(*schema.DN) error) error {
	manager.Lock()
	defer manager.Unlock()

	if manager.users == nil {
		return httpresponse.ErrNotImplemented.With("user schema not configured")
	}
	if manager.conn == nil {
		return httpresponse.ErrGatewayError.With("Not connected")
	}

	base := manager.users.DN.Join(manager.dn)
	if name == "" {
		return fn(base)
	}
	rdnAttr := userNamingAttribute(manager.users.ObjectClass)
	dn, err := schema.NewDN(rdnAttr + "=" + ldap.EscapeDN(name))
	if err != nil {
		return httpresponse.ErrBadRequest.Withf("invalid user name: %v", err)
	}
	return fn(dn.Join(base))
}

func userNamingAttribute(classes []string) string {
	if containsFold(classes, "user") {
		return "cn"
	}
	if containsFold(classes, "posixAccount") || containsFold(classes, "account") || containsFold(classes, "inetOrgPerson") {
		return "uid"
	}
	return "cn"
}

// nextUID finds the cn=lastuid device entry, reserves the next UID via an
// atomic delete-then-add modify, and returns the new UID. If the entry does
// not exist it is created with the initial value schema.InitialUID.
func (manager *Manager) nextUID(ctx context.Context) (int, error) {
	obj, err := manager.get(ctx, ldap.ScopeWholeSubtree, manager.dn.String(), "(&(objectClass=device)(cn=lastuid))")
	if err != nil {
		return 0, err
	}
	if obj == nil {
		dn, err := schema.NewDN("cn=lastuid")
		if err != nil {
			return 0, err
		}
		entryDN := dn.Join(manager.dn).String()
		addReq := ldap.NewAddRequest(entryDN, []ldap.Control{})
		addReq.Attribute("objectClass", []string{"top", "device"})
		addReq.Attribute("cn", []string{"lastuid"})
		addReq.Attribute("serialNumber", []string{strconv.Itoa(schema.InitialUID)})
		if err := manager.conn.Add(addReq); err != nil {
			return 0, ldaperr(err)
		}
		return schema.InitialUID, nil
	}

	serialPtr := obj.Get("serialNumber")
	if serialPtr == nil {
		return 0, httpresponse.ErrBadRequest.With("cn=lastuid has no serialNumber")
	}
	current, err := strconv.Atoi(types.Value(serialPtr))
	if err != nil {
		return 0, httpresponse.ErrBadRequest.Withf("cn=lastuid serialNumber is not an integer: %v", err)
	}
	next := current + 1

	modify := ldap.NewModifyRequest(obj.DN, []ldap.Control{})
	modify.Delete("serialNumber", []string{strconv.Itoa(current)})
	modify.Add("serialNumber", []string{strconv.Itoa(next)})
	if err := manager.conn.Modify(modify); err != nil {
		return 0, ldaperr(err)
	}

	return next, nil
}
