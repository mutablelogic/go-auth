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
	"math/rand/v2"
	"net/url"
	"strconv"
	"strings"
	"time"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	changes "github.com/mutablelogic/go-server/broadcaster/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
	trace "go.opentelemetry.io/otel/trace"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// The entries which have the last user and group IDs, in their
	// serialNumber, under the base DN
	lastUID = "lastuid"
	lastGID = "lastgid"

	// Times to try for the next ID, when another manager takes it, with a
	// random pause of up to idRetryPause between
	idRetries    = 10
	idRetryPause = 20 * time.Millisecond

	// userAccountControl values of an Active Directory user
	adNormalAccount   = "512"
	adDisabledAccount = "514"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ListUsers returns the users, which are the entries directly under the
// users' DN, which match the request's filter, and, when it has a group,
// are its members
func (manager *Manager) ListUsers(ctx context.Context, req schema.UserListRequest) (_ *schema.ObjectList, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.ListUsers", manager.spanAttrs(attribute.String("arg.req", types.Stringify(req)))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	base, err := manager.usersDN()
	if err != nil {
		return nil, err
	}

	// Only entries which have one of the users' classes, as others, such
	// as groups, can be beside them
	list := req.ListRequest
	list.Filter = types.Ptr(andFilter(req.Filter, classFilter(manager.userSelectClasses())))
	if req.Group == nil {
		return manager.list(ctx, ldap.ScopeSingleLevel, base.String(), list, nil)
	}

	// The group's members, by DN, which narrow the search by their RDNs,
	// and are kept, when they're one of them
	members, err := manager.groupMembers(ctx, base, *req.Group)
	if err != nil {
		return nil, err
	} else if len(members) == 0 {
		return &schema.ObjectList{}, nil
	}
	rdns := make([]string, 0, len(members))
	for _, member := range members {
		rdns = append(rdns, rdnFilter(member.RDNs[0]))
	}
	list.Filter = types.Ptr(andFilter(list.Filter, "(|"+strings.Join(rdns, "")+")"))
	return manager.list(ctx, ldap.ScopeSingleLevel, base.String(), list, func(user *schema.Object) bool {
		dn, err := ldap.ParseDN(user.DN)
		return err == nil && containsDN(members, dn)
	})
}

// GetUser returns the user with the name
func (manager *Manager) GetUser(ctx context.Context, name string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.GetUser", manager.spanAttrs(attribute.String("arg.name", name))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, _, err := manager.userDN(ctx, name)
	if err != nil {
		return nil, err
	}
	// The directory matches the classes, by any of their names, or OIDs, as
	// a list of users does
	user, err := manager.find(ctx, dn.String(), classFilter(manager.userSelectClasses()))
	if err != nil {
		return nil, err
	} else if user == nil {
		return nil, httpresponse.ErrNotFound.Withf("User %q not found", name)
	}
	return user, nil
}

// CreateUser adds a user with the name, and the attributes, and returns
// it. The users' object classes are added, which, when they aren't set,
// are those the directory has, such as inetOrgPerson and posixAccount, or
// Active Directory's user. A posixAccount without a uidNumber has the next
// one, and, with allocateGID, the same gidNumber.
//
// A password, in userPassword or unicodePwd, is set. An Active Directory
// user is created disabled, then has its password set, and is enabled, or
// is deleted when that fails. Without a password, it stays disabled.
func (manager *Manager) CreateUser(ctx context.Context, name string, attrs schema.Attrs, allocateGID bool) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.CreateUser", manager.spanAttrs(
		attribute.String("arg.name", name),
		attrNames(attrs),
		attribute.Bool("arg.allocate_gid", allocateGID),
	)...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, classes, err := manager.userDN(ctx, name)
	if err != nil {
		return nil, err
	}
	values, err := normalize(attrs)
	if err != nil {
		return nil, err
	}

	// The object classes, and the name
	objectClasses, _ := attrValues(values, "objectClass")
	for _, class := range append([]string{"top"}, classes...) {
		if !containsFold(objectClasses, class) {
			objectClasses = append(objectClasses, class)
		}
	}
	attrSet(values, "objectClass", objectClasses)
	attrSet(values, dn.RDNs[0].Attributes[0].Type, []string{name})

	// The user and group IDs of a posixAccount
	posix := containsFold(objectClasses, "posixAccount")
	if allocateGID {
		if !posix {
			return nil, httpresponse.ErrBadRequest.With("allocate_gid needs posixAccount users")
		} else if attrHas(values, "gidNumber") {
			return nil, httpresponse.ErrBadRequest.With("allocate_gid can't be used with a gidNumber")
		}
	}
	if posix && !attrHas(values, "uidNumber") {
		uid, err := manager.nextID(ctx, lastUID, schema.InitialUID)
		if err != nil {
			return nil, err
		}
		attrSet(values, "uidNumber", []string{strconv.Itoa(uid)})
	}
	if allocateGID {
		uid, _ := attrValues(values, "uidNumber")
		attrSet(values, "gidNumber", uid)
	}

	// An Active Directory user has its password set after it's created, and
	// is disabled until it has
	withPassword := false
	activeDirectory := containsFold(objectClasses, "user")
	if activeDirectory {
		withPassword = hasPassword(values)
		if !attrHas(values, "sAMAccountName") {
			attrSet(values, "sAMAccountName", []string{name})
		}
		attrSet(values, "userAccountControl", []string{adDisabledAccount})
	}

	// Create the user
	user, err := manager.create(ctx, dn.String(), values)
	if err != nil {
		return nil, err
	}
	if withPassword {
		if err := manager.enableUser(ctx, user.DN); err != nil {
			return nil, manager.undoCreate(ctx, user.DN, err)
		}
		if user, err = manager.get(ctx, user.DN); err != nil {
			return nil, err
		}
	}
	manager.publish(changes.ChangeCreate, schema.TableUser, name, "")
	return user, nil
}

// UpdateUser changes the user with the name, as Update does, and returns
// it. Changing its name renames it.
func (manager *Manager) UpdateUser(ctx context.Context, name string, attrs schema.Attrs) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.UpdateUser", manager.spanAttrs(attribute.String("arg.name", name), attrNames(attrs))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, _, err := manager.userDN(ctx, name)
	if err != nil {
		return nil, err
	}
	user, err := manager.update(ctx, dn, attrs)
	if err != nil {
		return nil, err
	}
	manager.publish(changes.ChangeUpdate, schema.TableUser, rdnValue(user.DN), name)
	return user, nil
}

// DeleteUser removes the user with the name, and returns it
func (manager *Manager) DeleteUser(ctx context.Context, name string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.DeleteUser", manager.spanAttrs(attribute.String("arg.name", name))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	dn, _, err := manager.userDN(ctx, name)
	if err != nil {
		return nil, err
	}
	user, err := manager.delete(ctx, dn.String())
	if err != nil {
		return nil, err
	}
	manager.publish(changes.ChangeDelete, schema.TableUser, name, "")
	return user, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// usersDN returns the absolute DN of the users, when the manager has them
func (manager *Manager) usersDN() (*schema.DN, error) {
	if manager.users == nil {
		return nil, httpresponse.ErrNotImplemented.With("The manager has no users")
	}
	if err := manager.connected(); err != nil {
		return nil, err
	}
	return manager.absdn(manager.users.DN.String())
}

// userDN returns the DN of the user with the name, under the users' DN, as
// its naming attribute, and the users' object classes
func (manager *Manager) userDN(ctx context.Context, name string) (*schema.DN, []string, error) {
	base, err := manager.usersDN()
	if err != nil {
		return nil, nil, err
	}
	if name == "" {
		return nil, nil, httpresponse.ErrBadRequest.With("A user needs a name")
	}
	classes, err := manager.userClasses(ctx)
	if err != nil {
		return nil, nil, err
	}
	rdn, err := schema.NewDN(userNamingAttribute(classes) + "=" + ldap.EscapeDN(name))
	if err != nil {
		return nil, nil, httpresponse.ErrBadRequest.Withf("Invalid user name: %v", err)
	}
	return rdn.Join(base), classes, nil
}

// userClasses returns the users' object classes, or, when they aren't set,
// one structural class which the directory has, of those well known, and
// the auxiliary posixAccount, when it has that, or the default
func (manager *Manager) userClasses(ctx context.Context) ([]string, error) {
	if len(manager.users.ObjectClass) > 0 {
		return manager.users.ObjectClass, nil
	}
	subschema, err := manager.subschema(ctx)
	if err != nil {
		return nil, err
	}
	if classes := subschema.choose(schema.WellKnownUserClasses, schema.WellKnownUserAuxiliaryClasses); len(classes) > 0 {
		return classes, nil
	}
	return schema.DefaultUserObjectClasses, nil
}

// userSelectClasses returns the classes which make an entry a user: those
// set, or else any of those well known, so users which another class was
// created with are users too
func (manager *Manager) userSelectClasses() []string {
	if len(manager.users.ObjectClass) > 0 {
		return manager.users.ObjectClass
	}
	return append(append([]string{}, schema.WellKnownUserClasses...), schema.WellKnownUserAuxiliaryClasses...)
}

// userNamingAttribute returns the attribute which names a user: cn for
// Active Directory, and uid for posixAccount, account and inetOrgPerson
func userNamingAttribute(classes []string) string {
	switch {
	case containsFold(classes, "user"):
		return "cn"
	case containsFold(classes, "posixAccount"), containsFold(classes, "account"), containsFold(classes, "inetOrgPerson"):
		return "uid"
	default:
		return "cn"
	}
}

// enableUser enables an Active Directory user, which has its password
func (manager *Manager) enableUser(ctx context.Context, dn string) error {
	modify := ldap.NewModifyRequest(dn, nil)
	modify.Replace("userAccountControl", []string{adNormalAccount})
	return ldaperr(manager.write(ctx, func(conn *ldap.Conn) error { return conn.Modify(modify) }))
}

// nextID returns the next ID, from the serialNumber of the entry with the
// name, such as cn=lastuid, under the base DN, which is created with the
// initial ID when there's none. The old value is deleted, and the new one
// added, in one request, which fails when another manager has changed it,
// so it's tried again.
func (manager *Manager) nextID(ctx context.Context, name string, initial int) (int, error) {
	dn := "cn=" + name + "," + manager.dn.String()
	for retry := range idRetries {
		if retry > 0 {
			trace.SpanFromContext(ctx).AddEvent("ID taken, retrying", trace.WithAttributes(attribute.String("dn", dn)))
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			case <-time.After(rand.N(idRetryPause)):
			}
		}
		entry, err := manager.get(ctx, dn, "serialNumber")
		if errors.Is(err, httpresponse.ErrNotFound) {
			_, err := manager.create(ctx, dn, url.Values{
				"objectClass":  {"top", "device"},
				"cn":           {name},
				"serialNumber": {strconv.Itoa(initial)},
			})
			if errors.Is(err, httpresponse.ErrConflict) {
				continue
			} else if err != nil {
				return 0, err
			}
			return initial, nil
		} else if err != nil {
			return 0, err
		}

		value := entry.Get("serialNumber")
		if value == nil {
			return 0, httpresponse.ErrInternalError.Withf("%s has no serialNumber", dn)
		}
		current, err := strconv.Atoi(*value)
		if err != nil {
			return 0, httpresponse.ErrInternalError.Withf("%s has a serialNumber which isn't a number: %q", dn, *value)
		}
		modify := ldap.NewModifyRequest(entry.DN, nil)
		modify.Delete("serialNumber", []string{strconv.Itoa(current)})
		modify.Add("serialNumber", []string{strconv.Itoa(current + 1)})
		err = ldaperr(manager.write(ctx, func(conn *ldap.Conn) error { return conn.Modify(modify) }))
		if errors.Is(err, httpresponse.ErrNotFound) {
			// Another manager changed it first
			continue
		} else if err != nil {
			return 0, err
		}
		return current + 1, nil
	}
	return 0, httpresponse.ErrConflict.With("The next ID is taken, try again")
}

// create adds the entry at the absolute DN, with the attributes, and
// returns it
func (manager *Manager) create(ctx context.Context, dn string, values url.Values) (*schema.Object, error) {
	values, err := (schema.ObjectPutRequest{Attrs: schema.Attrs(values)}).ValidateCreate()
	if err != nil {
		return nil, auth.HTTPError(err)
	}

	// A password is set after the entry is created, so it's hashed
	password, user, err := takePassword(values)
	if err != nil {
		return nil, err
	}
	add := ldap.NewAddRequest(dn, nil)
	for key, values := range values {
		if len(values) > 0 {
			add.Attribute(key, values)
		}
	}
	err = manager.write(ctx, func(conn *ldap.Conn) error { return conn.Add(add) })

	// A class which needs a userPassword, such as simpleSecurityObject, is
	// added with a random one, which nobody knows, and the password, hashed,
	// replaces it
	if user && ldap.IsErrorWithCode(err, ldap.LDAPResultObjectClassViolation) {
		placeholder, randErr := randomPassword()
		if randErr != nil {
			return nil, randErr
		}
		add.Attribute("userPassword", []string{placeholder})
		err = manager.write(ctx, func(conn *ldap.Conn) error { return conn.Add(add) })
	}
	if err != nil {
		return nil, ldaperr(err)
	}
	if password != "" {
		if err := manager.setPassword(ctx, dn, password); err != nil {
			return nil, manager.undoCreate(ctx, dn, err)
		}
	}
	return manager.get(ctx, dn)
}

// undoCreate deletes the entry which was created, when what followed
// failed, on a new connection, since the manager's can be lost when the
// context is cancelled, and returns the error
func (manager *Manager) undoCreate(ctx context.Context, dn string, err error) error {
	if deleteErr := manager.cleanup(ctx, func(conn *ldap.Conn) error { return conn.Del(ldap.NewDelRequest(dn, nil)) }); deleteErr != nil {
		return errors.Join(err, httpresponse.ErrInternalError.Withf("%q isn't deleted: %v", dn, deleteErr))
	}
	return err
}

// normalize returns the attributes, with names trimmed and checked, and
// values which aren't empty, before anything is read from them
func normalize(attrs schema.Attrs) (url.Values, error) {
	if len(attrs) == 0 {
		return url.Values{}, nil
	}
	values, err := (schema.ObjectPutRequest{Attrs: attrs}).ValidateUpdate()
	if err != nil {
		return nil, auth.HTTPError(err)
	}
	return values, nil
}

// attrHas returns whether the attribute, whose name is in any case, has a
// value
func attrHas(attrs url.Values, name string) bool {
	values, ok := attrValues(attrs, name)
	return ok && len(values) > 0
}

// attrSet sets the attribute's values, whose name is in any case
func attrSet(attrs url.Values, name string, values []string) {
	attrDelete(attrs, name)
	attrs[name] = values
}

// attrDelete removes the attribute, whose name is in any case
func attrDelete(attrs url.Values, name string) {
	for key := range attrs {
		if strings.EqualFold(key, name) {
			delete(attrs, key)
		}
	}
}
