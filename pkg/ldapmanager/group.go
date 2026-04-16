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
	schema "github.com/mutablelogic/go-auth/schema/ldap"
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

// Update attributes for a group. It will replace the attributes where the
// values are not empty, and delete the attributes where the values are empty.
// If the request changes the naming attribute, the entry is renamed first and
// then modified. The updated group is returned.
func (manager *Manager) UpdateGroup(ctx context.Context, cn string, attrs url.Values) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withGroups(cn, func(groupDN *schema.DN) error {
		attrs, err := (schema.ObjectPutRequest{Attrs: attrs}).ValidateUpdate()
		if err != nil {
			return err
		}

		currentDN, targetDN, newRDN, rename, err := updateTargetDN(groupDN, attrs)
		if err != nil {
			return err
		}
		if rename {
			if err := manager.conn.ModifyDN(ldap.NewModifyDNRequest(currentDN, newRDN, true, "")); err != nil {
				return ldaperr(err)
			}
		}

		modifyReq, hasChanges := newModifyRequest(targetDN, attrs, groupDN, rename)
		if hasChanges {
			if err := manager.conn.Modify(modifyReq); err != nil {
				return ldaperr(err)
			}
		}

		result, err = manager.get(ctx, ldap.ScopeBaseObject, targetDN, "(objectClass=*)")
		return err
	})
}

// Add users to a group, and return the updated group. Membership changes are
// applied with a single LDAP modify request on the group entry.
func (manager *Manager) AddGroupUsers(ctx context.Context, groupcn string, usercn ...string) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withGroups(groupcn, func(groupDN *schema.DN) error {
		if len(usercn) == 0 {
			return httpresponse.ErrBadRequest.With("at least one user is required")
		}

		group, err := manager.get(ctx, ldap.ScopeBaseObject, groupDN.String(), "(objectClass=*)")
		if err != nil {
			if errors.Is(err, httpresponse.ErrNotFound) {
				return httpresponse.ErrNotFound.Withf("group %q not found", groupcn)
			}
			return ldaperr(err)
		}
		if group == nil {
			return httpresponse.ErrNotFound.Withf("group %q not found", groupcn)
		}

		attrs := groupMembershipAttrs(group.GetAll("objectClass"))
		if len(attrs) == 0 {
			return httpresponse.ErrBadRequest.With("group does not support membership attributes")
		}

		members, err := manager.resolveGroupUsers(ctx, usercn...)
		if err != nil {
			return err
		}

		modifyReq := ldap.NewModifyRequest(group.DN, []ldap.Control{})
		for _, attr := range attrs {
			current := group.GetAll(attr)
			for _, value := range groupMembershipMissing(attr, current, members) {
				modifyReq.Add(attr, []string{value})
			}
		}
		if len(modifyReq.Changes) == 0 {
			result = group
			return nil
		}

		if err := manager.conn.Modify(modifyReq); err != nil {
			return ldaperr(err)
		}

		result, err = manager.get(ctx, ldap.ScopeBaseObject, group.DN, "(objectClass=*)")
		return err
	})
}

// Remove users from a group, and return the updated group. Membership changes
// are applied with a single LDAP modify request on the group entry.
func (manager *Manager) RemoveGroupUsers(ctx context.Context, groupcn string, usercn ...string) (*schema.Object, error) {
	var result *schema.Object
	return result, manager.withGroups(groupcn, func(groupDN *schema.DN) error {
		if len(usercn) == 0 {
			return httpresponse.ErrBadRequest.With("at least one user is required")
		}

		group, err := manager.get(ctx, ldap.ScopeBaseObject, groupDN.String(), "(objectClass=*)")
		if err != nil {
			if errors.Is(err, httpresponse.ErrNotFound) {
				return httpresponse.ErrNotFound.Withf("group %q not found", groupcn)
			}
			return ldaperr(err)
		}
		if group == nil {
			return httpresponse.ErrNotFound.Withf("group %q not found", groupcn)
		}

		attrs := groupMembershipAttrs(group.GetAll("objectClass"))
		if len(attrs) == 0 {
			return httpresponse.ErrBadRequest.With("group does not support membership attributes")
		}

		members, err := manager.resolveGroupUsers(ctx, usercn...)
		if err != nil {
			return err
		}

		modifyReq := ldap.NewModifyRequest(group.DN, []ldap.Control{})
		for _, attr := range attrs {
			current := group.GetAll(attr)
			for _, value := range groupMembershipPresent(attr, current, members) {
				modifyReq.Delete(attr, []string{value})
			}
		}
		if len(modifyReq.Changes) == 0 {
			result = group
			return nil
		}

		if err := manager.conn.Modify(modifyReq); err != nil {
			return ldaperr(err)
		}

		result, err = manager.get(ctx, ldap.ScopeBaseObject, group.DN, "(objectClass=*)")
		return err
	})
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

func groupMembershipAttrs(classes []string) []string {
	attrs := make([]string, 0, 2)
	if containsFold(classes, "groupOfUniqueNames") {
		attrs = append(attrs, "uniqueMember")
	} else if containsFold(classes, "groupOfNames") || containsFold(classes, "groupOfMembers") || containsFold(classes, "group") || !containsFold(classes, "posixGroup") {
		attrs = append(attrs, "member")
	}
	if containsFold(classes, "posixGroup") {
		attrs = append(attrs, "memberUid")
	}
	return attrs
}

func groupMembershipValues(attr string, members []*schema.Object) []string {
	values := make([]string, 0, len(members))
	seen := make(map[string]struct{}, len(members))
	for _, member := range members {
		if member == nil {
			continue
		}
		var value string
		switch attr {
		case "memberUid":
			if uid := member.Get("uid"); uid != nil && *uid != "" {
				value = *uid
			} else if cn := member.Get("cn"); cn != nil {
				value = *cn
			}
		case "member", "uniqueMember":
			value = member.DN
		}
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		values = append(values, value)
	}
	return values
}

func groupMembershipMissing(attr string, current []string, members []*schema.Object) []string {
	values := groupMembershipValues(attr, members)
	missing := make([]string, 0, len(values))
	for _, value := range values {
		if !containsFold(current, value) {
			missing = append(missing, value)
		}
	}
	return missing
}

func groupMembershipPresent(attr string, current []string, members []*schema.Object) []string {
	values := groupMembershipValues(attr, members)
	present := make([]string, 0, len(values))
	for _, value := range values {
		if containsFold(current, value) {
			present = append(present, value)
		}
	}
	return present
}

// resolveGroupUsers resolves user names to LDAP objects while the manager lock
// is already held by the caller.
func (manager *Manager) resolveGroupUsers(ctx context.Context, usercn ...string) ([]*schema.Object, error) {
	if manager.users == nil {
		return nil, httpresponse.ErrNotImplemented.With("user schema not configured")
	}
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	base := manager.users.DN.Join(manager.dn)
	rdnAttr := userNamingAttribute(manager.users.ObjectClass)
	result := make([]*schema.Object, 0, len(usercn))
	seen := make(map[string]struct{}, len(usercn))
	for _, name := range usercn {
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		dn, err := schema.NewDN(rdnAttr + "=" + ldap.EscapeDN(name))
		if err != nil {
			return nil, httpresponse.ErrBadRequest.Withf("invalid user name: %v", err)
		}
		user, err := manager.get(ctx, ldap.ScopeBaseObject, dn.Join(base).String(), "(objectClass=*)")
		if err != nil {
			if errors.Is(err, httpresponse.ErrNotFound) {
				return nil, httpresponse.ErrNotFound.Withf("user %q not found", name)
			}
			return nil, ldaperr(err)
		}
		if user == nil {
			return nil, httpresponse.ErrNotFound.Withf("user %q not found", name)
		}
		result = append(result, user)
	}
	return result, nil
}
