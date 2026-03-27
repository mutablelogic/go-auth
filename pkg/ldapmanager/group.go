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
	"strconv"
	"strings"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	ldap "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - GROUPS

// Return all groups
func (manager *Manager) ListGroups(ctx context.Context, request schema.ObjectListRequest) (*schema.ObjectList, error) {
	var result *schema.ObjectList
	return result, manager.withGroups("", func(searchBase *schema.DN) error {
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

// Get a group by cn
func (manager *Manager) GetGroup(ctx context.Context, cn string) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withGroups(cn, func(dn *schema.DN) error {
		var err error
		result, err = manager.get(ctx, ldap.ScopeBaseObject, dn.String(), "(objectClass=*)")
		return err
	})
}

// Delete a group by cn
func (manager *Manager) DeleteGroup(ctx context.Context, cn string) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withGroups(cn, func(dn *schema.DN) error {
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

// Create a group with optional additional attributes. If posixGroup is one of
// the configured group object classes and no gidNumber is supplied, the next
// available GID is allocated atomically from the cn=lastgid device entry.
func (manager *Manager) CreateGroup(ctx context.Context, cn string, attrs url.Values) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withGroups(cn, func(groupDN *schema.DN) error {
		searchReq := ldap.NewSearchRequest(
			groupDN.String(),
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
			return httpresponse.ErrConflict.With("group already exists")
		} else if ldapErrorCode(err) != ldap.LDAPResultNoSuchObject {
			return ldaperr(err)
		}

		if attrs == nil {
			attrs = make(url.Values)
		}
		classes := manager.groups.ObjectClass
		if len(classes) == 0 {
			classes = schema.DefaultGroupObjectClasses
		}
		existing := attrValues(attrs, "objectClass")
		// Always include top as the root abstract class
		if !containsFold(existing, "top") {
			existing = append([]string{"top"}, existing...)
		}
		for _, class := range classes {
			if !containsFold(existing, class) {
				existing = append(existing, class)
			}
		}
		attrSet(attrs, "objectClass", existing)
		attrSet(attrs, "cn", []string{cn})
		ensureGroupRequiredAttrs(attrs, groupDN.String(), classes)

		if containsFold(classes, "posixGroup") {
			if !attrHas(attrs, "gidNumber") {
				gid, err := manager.nextGID(ctx)
				if err != nil {
					return err
				}
				attrSet(attrs, "gidNumber", []string{strconv.Itoa(gid)})
			}
		}

		addReq := ldap.NewAddRequest(groupDN.String(), []ldap.Control{})
		for key, values := range attrs {
			if len(values) > 0 {
				addReq.Attribute(key, values)
			}
		}
		if err := manager.conn.Add(addReq); err != nil {
			return ldaperr(err)
		}
		var err error
		result, err = manager.get(ctx, ldap.ScopeBaseObject, addReq.DN, "(objectClass=*)")
		return err
	})
}

// Add a user to a group, and return the group
func (manager *Manager) AddGroupUser(ctx context.Context, cn, user string) (*schema.Object, error) {
	// TODO
	// Use uniqueMember for groupOfUniqueNames,
	// use memberUid for posixGroup
	// use member for groupOfNames or if not posix
	return nil, httpresponse.ErrNotImplemented.With("AddGroupUser not implemented")
}

// Remove a user from a group, and return the group
func (manager *Manager) RemoveGroupUser(ctx context.Context, cn, user string) (*schema.Object, error) {
	// TODO
	// Use uniqueMember for groupOfUniqueNames,
	// use memberUid for posixGroup
	// use member for groupOfNames or if not posix
	return nil, httpresponse.ErrNotImplemented.With("RemoveGroupUser not implemented")
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - GROUPS

// withGroups acquires the manager lock, validates that the group schema and
// connection are ready, then calls fn with the lock held. If cn is non-empty
// the resolved DN is cn=<cn>,<groupBase>; otherwise it is the group base DN.
func (manager *Manager) withGroups(cn string, fn func(*schema.DN) error) error {
	manager.Lock()
	defer manager.Unlock()

	if manager.groups == nil {
		return httpresponse.ErrNotImplemented.With("group schema not configured")
	}
	if manager.conn == nil {
		return httpresponse.ErrGatewayError.With("Not connected")
	}

	base := manager.groups.DN.Join(manager.dn)
	if cn == "" {
		return fn(base)
	}
	dn, err := schema.NewDN("cn=" + ldap.EscapeDN(cn))
	if err != nil {
		return httpresponse.ErrBadRequest.Withf("invalid group name: %v", err)
	}
	return fn(dn.Join(base))
}

// nextGID finds the cn=lastgid device entry, reserves the next GID via an
// atomic delete-then-add modify (so concurrent callers cannot grab the same
// value), and returns the new GID. If the entry does not exist it is created
// with the initial value schema.InitialGID.
func (manager *Manager) nextGID(ctx context.Context) (int, error) {
	obj, err := manager.get(ctx, ldap.ScopeWholeSubtree, manager.dn.String(), "(&(objectClass=device)(cn=lastgid))")
	if err != nil {
		return 0, err
	}
	if obj == nil {
		// Create the lastgid device entry with the initial value
		dn, err := schema.NewDN("cn=lastgid")
		if err != nil {
			return 0, err
		}
		entryDN := dn.Join(manager.dn).String()
		addReq := ldap.NewAddRequest(entryDN, []ldap.Control{})
		addReq.Attribute("objectClass", []string{"top", "device"})
		addReq.Attribute("cn", []string{"lastgid"})
		addReq.Attribute("serialNumber", []string{strconv.Itoa(schema.InitialGID)})
		if err := manager.conn.Add(addReq); err != nil {
			return 0, ldaperr(err)
		}
		return schema.InitialGID, nil
	}

	serialPtr := obj.Get("serialNumber")
	if serialPtr == nil {
		return 0, httpresponse.ErrBadRequest.With("cn=lastgid has no serialNumber")
	}
	current, err := strconv.Atoi(types.Value(serialPtr))
	if err != nil {
		return 0, httpresponse.ErrBadRequest.Withf("cn=lastgid serialNumber is not an integer: %v", err)
	}
	next := current + 1

	// Atomic increment: delete the current value, add the new one.
	// If another caller modified serialNumber concurrently the delete will fail,
	// which prevents duplicate GID allocation.
	modify := ldap.NewModifyRequest(obj.DN, []ldap.Control{})
	modify.Delete("serialNumber", []string{strconv.Itoa(current)})
	modify.Add("serialNumber", []string{strconv.Itoa(next)})
	if err := manager.conn.Modify(modify); err != nil {
		return 0, ldaperr(err)
	}

	return next, nil
}

// containsFold reports whether s appears in values with case-insensitive comparison.
func containsFold(values []string, s string) bool {
	for _, v := range values {
		if strings.EqualFold(v, s) {
			return true
		}
	}
	return false
}

func ensureGroupRequiredAttrs(attrs url.Values, groupDN string, classes []string) {
	if containsFold(classes, "groupOfUniqueNames") {
		if !attrHas(attrs, "uniqueMember") {
			attrSet(attrs, "uniqueMember", []string{groupDN})
		}
		return
	}
	if containsFold(classes, "groupOfNames") || containsFold(classes, "groupOfMembers") {
		if !attrHas(attrs, "member") {
			attrSet(attrs, "member", []string{groupDN})
		}
	}
}

func attrHas(attrs url.Values, name string) bool {
	_, ok := attrKey(attrs, name)
	return ok
}

func attrValues(attrs url.Values, name string) []string {
	if key, ok := attrKey(attrs, name); ok {
		return attrs[key]
	}
	return nil
}

func attrSet(attrs url.Values, name string, values []string) {
	if key, ok := attrKey(attrs, name); ok {
		attrs[key] = values
	} else {
		attrs[name] = values
	}
}

func attrKey(attrs url.Values, name string) (string, bool) {
	for key := range attrs {
		if strings.EqualFold(key, name) {
			return key, true
		}
	}
	return "", false
}
