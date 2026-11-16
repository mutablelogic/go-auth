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

package manager

import (
	"context"
	"errors"
	"net/url"
	"strconv"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ListGroups returns the groups, which are the entries directly under the
// groups' DN, which match the request's filter
func (manager *Manager) ListGroups(ctx context.Context, req schema.ObjectListRequest) (_ *schema.ObjectList, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.ListGroups", manager.spanAttrs(attribute.String("arg.req", types.Stringify(req)))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	base, err := manager.groupsDN()
	if err != nil {
		return nil, err
	}
	return manager.list(ctx, ldap.ScopeSingleLevel, base.String(), req)
}

// GetGroup returns the group with the name
func (manager *Manager) GetGroup(ctx context.Context, name string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.GetGroup", manager.spanAttrs(attribute.String("arg.name", name))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, err := manager.groupDN(name)
	if err != nil {
		return nil, err
	}
	return manager.get(ctx, dn.String())
}

// CreateGroup adds a group with the name, as its cn, and the attributes,
// and returns it. The groups' object classes are added, which, when they
// aren't set, are those the directory has, such as groupOfNames and
// posixGroup, or Active Directory's group. A posixGroup without a gidNumber
// has the next one. A group whose class needs a member has itself, as
// groupOfNames and groupOfUniqueNames do.
func (manager *Manager) CreateGroup(ctx context.Context, name string, attrs schema.Attrs) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.CreateGroup", manager.spanAttrs(attribute.String("arg.name", name), attrNames(attrs))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, err := manager.groupDN(name)
	if err != nil {
		return nil, err
	}
	classes, err := manager.groupClasses(ctx)
	if err != nil {
		return nil, err
	}
	values := url.Values{}
	for key, value := range attrs {
		values[key] = append([]string(nil), value...)
	}

	// The object classes, and the name
	objectClasses, _ := attrValues(values, "objectClass")
	for _, class := range append([]string{"top"}, classes...) {
		if !containsFold(objectClasses, class) {
			objectClasses = append(objectClasses, class)
		}
	}
	attrSet(values, "objectClass", objectClasses)
	attrSet(values, "cn", []string{name})

	// A class which needs a member has the group itself
	if containsFold(objectClasses, "groupOfUniqueNames") {
		if _, ok := attrValues(values, "uniqueMember"); !ok {
			attrSet(values, "uniqueMember", []string{dn.String()})
		}
	} else if containsFold(objectClasses, "groupOfNames") {
		if _, ok := attrValues(values, "member"); !ok {
			attrSet(values, "member", []string{dn.String()})
		}
	}

	// The group ID of a posixGroup
	if _, ok := attrValues(values, "gidNumber"); containsFold(objectClasses, "posixGroup") && !ok {
		gid, err := manager.nextID(ctx, lastGID, schema.InitialGID)
		if err != nil {
			return nil, err
		}
		attrSet(values, "gidNumber", []string{strconv.Itoa(gid)})
	}

	return manager.create(ctx, dn.String(), values)
}

// UpdateGroup changes the group with the name, as Update does, and returns
// it. Changing its cn renames it.
func (manager *Manager) UpdateGroup(ctx context.Context, name string, attrs schema.Attrs) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.UpdateGroup", manager.spanAttrs(attribute.String("arg.name", name), attrNames(attrs))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, err := manager.groupDN(name)
	if err != nil {
		return nil, err
	}
	return manager.update(ctx, dn, attrs)
}

// DeleteGroup removes the group with the name, and returns it
func (manager *Manager) DeleteGroup(ctx context.Context, name string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.DeleteGroup", manager.spanAttrs(attribute.String("arg.name", name))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, err := manager.groupDN(name)
	if err != nil {
		return nil, err
	}
	return manager.delete(ctx, dn.String())
}

// AddGroupUsers adds the users, by name, to the group, in one request, and
// returns it. Users who are members already are left as they are.
func (manager *Manager) AddGroupUsers(ctx context.Context, group string, users ...string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.AddGroupUsers", manager.spanAttrs(attribute.String("arg.group", group), attribute.StringSlice("arg.users", users))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.changeMembers(ctx, group, users, true)
}

// RemoveGroupUsers removes the users, by name, from the group, in one
// request, and returns it. Users who aren't members are left as they are.
func (manager *Manager) RemoveGroupUsers(ctx context.Context, group string, users ...string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.RemoveGroupUsers", manager.spanAttrs(attribute.String("arg.group", group), attribute.StringSlice("arg.users", users))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.changeMembers(ctx, group, users, false)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// groupsDN returns the absolute DN of the groups, when the manager has them
func (manager *Manager) groupsDN() (*schema.DN, error) {
	if manager.groups == nil {
		return nil, httpresponse.ErrNotImplemented.With("The manager has no groups")
	}
	if err := manager.connected(); err != nil {
		return nil, err
	}
	return manager.absdn(manager.groups.DN.String())
}

// groupDN returns the DN of the group with the name, as its cn, under the
// groups' DN
func (manager *Manager) groupDN(name string) (*schema.DN, error) {
	base, err := manager.groupsDN()
	if err != nil {
		return nil, err
	}
	if name == "" {
		return nil, httpresponse.ErrBadRequest.With("A group needs a name")
	}
	rdn, err := schema.NewDN("cn=" + ldap.EscapeDN(name))
	if err != nil {
		return nil, httpresponse.ErrBadRequest.Withf("Invalid group name: %v", err)
	}
	return rdn.Join(base), nil
}

// groupClasses returns the groups' object classes, or, when they aren't
// set, one structural class which the directory has, of those well known,
// and the auxiliary posixGroup, when it has that, or the default
func (manager *Manager) groupClasses(ctx context.Context) ([]string, error) {
	if len(manager.groups.ObjectClass) > 0 {
		return manager.groups.ObjectClass, nil
	}
	subschema, err := manager.subschema(ctx)
	if err != nil {
		return nil, err
	}
	if classes := subschema.choose(schema.WellKnownGroupClasses, []string{"posixGroup"}); len(classes) > 0 {
		return classes, nil
	}
	return schema.DefaultGroupObjectClasses, nil
}

// changeMembers adds the users to the group, or removes them, in one
// request, and returns it
func (manager *Manager) changeMembers(ctx context.Context, name string, users []string, add bool) (*schema.Object, error) {
	if len(users) == 0 {
		return nil, httpresponse.ErrBadRequest.With("At least one user is needed")
	}
	dn, err := manager.groupDN(name)
	if err != nil {
		return nil, err
	}
	group, err := manager.get(ctx, dn.String())
	if err != nil {
		return nil, err
	}
	attrs := memberAttrs(group.GetAll("objectClass"))
	if len(attrs) == 0 {
		return nil, httpresponse.ErrBadRequest.Withf("%q has no members", name)
	}
	members, err := manager.members(ctx, users)
	if err != nil {
		return nil, err
	}

	// Add the values which are missing, or delete those which are there, as
	// the directory has them
	modify := ldap.NewModifyRequest(group.DN, nil)
	required := requiredMember(group.GetAll("objectClass"))
	for _, attr := range attrs {
		current := group.GetAll(attr)
		removed := 0
		for _, value := range memberValues(attr, members) {
			existing := findMember(attr, current, value)
			if add && existing == "" {
				modify.Add(attr, []string{value})
			} else if !add && existing != "" {
				modify.Delete(attr, []string{existing})
				removed++
			}
		}

		// A group whose class needs a member, which would have none, has
		// itself, in the same request
		if removed > 0 && removed == len(current) && attr == required {
			modify.Add(attr, []string{group.DN})
		}
	}
	if len(modify.Changes) == 0 {
		return group, nil
	}
	if err := manager.write(ctx, func(conn *ldap.Conn) error { return conn.Modify(modify) }); err != nil {
		return nil, ldaperr(err)
	}
	return manager.get(ctx, group.DN)
}

// members returns the users with the names, once each, or not found
func (manager *Manager) members(ctx context.Context, names []string) ([]*schema.Object, error) {
	result := make([]*schema.Object, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			continue
		}
		seen[name] = true
		dn, _, err := manager.userDN(ctx, name)
		if err != nil {
			return nil, err
		}
		user, err := manager.get(ctx, dn.String())
		if errors.Is(err, httpresponse.ErrNotFound) {
			return nil, httpresponse.ErrNotFound.Withf("User %q not found", name)
		} else if err != nil {
			return nil, err
		}
		result = append(result, user)
	}
	return result, nil
}

// memberAttrs returns the attributes which have a group's members, for its
// object classes: uniqueMember or member, which have their DNs, and
// memberUid for a posixGroup, which has their uid
func memberAttrs(classes []string) []string {
	attrs := make([]string, 0, 2)
	switch {
	case containsFold(classes, "groupOfUniqueNames"):
		attrs = append(attrs, "uniqueMember")
	case containsFold(classes, "groupOfNames"), containsFold(classes, "groupOfMembers"), containsFold(classes, "group"), !containsFold(classes, "posixGroup"):
		attrs = append(attrs, "member")
	}
	if containsFold(classes, "posixGroup") {
		attrs = append(attrs, "memberUid")
	}
	return attrs
}

// requiredMember returns the attribute which a group of the classes needs
// a value of: uniqueMember for groupOfUniqueNames, and member for
// groupOfNames, or none
func requiredMember(classes []string) string {
	switch {
	case containsFold(classes, "groupOfUniqueNames"):
		return "uniqueMember"
	case containsFold(classes, "groupOfNames"):
		return "member"
	default:
		return ""
	}
}

// memberValues returns the values of the attribute for the users, once
// each, as findMember matches them: their uid, or cn, for memberUid, and
// their DN otherwise
func memberValues(attr string, users []*schema.Object) []string {
	values := make([]string, 0, len(users))
	for _, user := range users {
		value := user.DN
		if attr == "memberUid" {
			value = ""
			if uid := user.Get("uid"); uid != nil {
				value = *uid
			} else if cn := user.Get("cn"); cn != nil {
				value = *cn
			}
		}
		if value != "" && findMember(attr, values, value) == "" {
			values = append(values, value)
		}
	}
	return values
}

// findMember returns the current value which is the member's, as the
// directory has it, or empty. DNs are equal in any case, and spacing.
func findMember(attr string, current []string, value string) string {
	for _, existing := range current {
		if attr == "memberUid" {
			if existing == value {
				return existing
			}
		} else if a, err := ldap.ParseDN(existing); err == nil {
			if b, err := ldap.ParseDN(value); err == nil && a.EqualFold(b) {
				return existing
			}
		}
	}
	return ""
}
