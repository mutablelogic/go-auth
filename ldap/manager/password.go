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
	"crypto/rand"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf16"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	changes "github.com/mutablelogic/go-server/broadcaster/schema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Bind checks the password of the entry, whose DN is under the base DN, or
// relative to it, and returns the entry, or ErrNotAuthorized. It binds on a
// connection of its own, so the manager's stays bound as its user.
func (manager *Manager) Bind(ctx context.Context, dn, password string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Bind", manager.spanAttrs(attribute.String("arg.dn", dn))...)
	defer func() { endSpan(err) }()

	// An empty password would be an unauthenticated bind, which succeeds
	if password == "" {
		return nil, httpresponse.ErrNotAuthorized.With("Password is required")
	}
	absdn, err := manager.absdn(dn)
	if err != nil {
		return nil, err
	}
	conn, err := manager.bindAs(ctx, absdn.String(), password)
	if err != nil {
		return nil, err
	}
	if err := ldapDisconnect(conn); err != nil {
		return nil, err
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.connected(); err != nil {
		return nil, err
	}
	return manager.get(ctx, absdn.String())
}

// ChangePassword sets the password of the entry, whose DN is under the base
// DN, or relative to it, to the request's new password, or one which is
// generated, which is returned, when it's empty. With the old password, it
// binds as the entry, which changes its own password, so the old one is
// checked. Without it, the manager's user resets it.
//
// An Active Directory user, whose objectClass is "user", has its unicodePwd
// set, which needs ldaps. Other directories have the password modify
// operation (RFC 3062).
func (manager *Manager) ChangePassword(ctx context.Context, dn string, req schema.ObjectPasswordRequest) (_ *schema.PasswordResponse, err error) {
	// The request has passwords, so isn't an attribute
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.ChangePassword", manager.spanAttrs(
		attribute.String("arg.dn", dn),
		attribute.Bool("arg.old", req.Old != ""),
		attribute.Bool("arg.generate", req.New == nil || *req.New == ""),
	)...)
	defer func() { endSpan(err) }()

	absdn, err := manager.absdn(dn)
	if err != nil {
		return nil, err
	}

	// The new password, or a generated one
	var generated *string
	password := ""
	if req.New != nil {
		password = *req.New
	}
	if password == "" {
		if password, err = randomPassword(); err != nil {
			return nil, err
		}
		generated = &password
	}

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.connected(); err != nil {
		return nil, err
	}
	object, err := manager.get(ctx, absdn.String(), "objectClass")
	if err != nil {
		return nil, err
	}
	activeDirectory := containsFold(object.GetAll("objectClass"), "user")
	if activeDirectory && manager.tls == nil {
		return nil, httpresponse.ErrBadRequest.With("Active Directory passwords need ldaps")
	}

	// Change the password as the entry, with the old password, or reset it,
	// on a connection which is closed when the context is cancelled
	change := func(conn *ldap.Conn) error {
		if activeDirectory {
			return setUnicodePwd(conn, object.DN, req.Old, password)
		}
		_, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(object.DN, req.Old, password))
		return err
	}
	if req.Old != "" {
		conn, err := manager.bindAs(ctx, object.DN, req.Old)
		if err != nil {
			return nil, err
		}
		defer ldapDisconnect(conn)
		if err := whileOpen(ctx, conn, func() error { return change(conn) }); err != nil {
			return nil, ldaperr(err)
		}
	} else if err := manager.write(ctx, change); err != nil {
		return nil, ldaperr(err)
	}

	// Return the entry, with the generated password
	if object, err = manager.get(ctx, object.DN); err != nil {
		return nil, err
	}
	manager.publish(changes.ChangeUpdate, schema.TableObject, object.DN, "")
	return object.WithPassword(generated), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// bindAs returns a new connection to the directory, bound as the DN, or
// ErrNotAuthorized
func (manager *Manager) bindAs(ctx context.Context, dn, password string) (*ldap.Conn, error) {
	conn, err := ldapConnect(ctx, manager.Host(), manager.Port(), manager.tls)
	if err != nil {
		return nil, ldaperr(err)
	}
	if err := whileOpen(ctx, conn, func() error { return conn.Bind(dn, password) }); err != nil {
		return nil, errors.Join(ldaperr(err), ldapDisconnect(conn))
	}
	return conn, nil
}

// setUnicodePwd resets an Active Directory password, or, with the old one,
// changes it, which deletes the old value and adds the new one in the same
// request (MS-ADTS 3.1.1.3.1.5)
func setUnicodePwd(conn *ldap.Conn, dn, old, password string) error {
	modify := ldap.NewModifyRequest(dn, nil)
	if old == "" {
		modify.Replace("unicodePwd", []string{unicodePwd(password)})
	} else {
		modify.Delete("unicodePwd", []string{unicodePwd(old)})
		modify.Add("unicodePwd", []string{unicodePwd(password)})
	}
	return conn.Modify(modify)
}

// unicodePwd is the password as Active Directory has it: quoted, in UTF-16LE
func unicodePwd(password string) string {
	encoded := utf16.Encode([]rune(`"` + password + `"`))
	buf := make([]byte, len(encoded)*2)
	for i, value := range encoded {
		binary.LittleEndian.PutUint16(buf[i*2:], value)
	}
	return string(buf)
}

// randomPassword returns a password of 24 characters, from 18 random bytes,
// with at least three of upper case, lower case, digits and symbols, which
// Active Directory's complexity rule needs
func randomPassword() (string, error) {
	buf := make([]byte, 18)
	for {
		if _, err := rand.Read(buf); err != nil {
			return "", err
		}
		if password := base64.RawURLEncoding.EncodeToString(buf); passwordClasses(password) >= 3 {
			return password, nil
		}
	}
}

// passwordClasses returns how many of upper case, lower case, digits and
// symbols the password has
func passwordClasses(password string) int {
	var upper, lower, digit, symbol int
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			upper = 1
		case unicode.IsLower(r):
			lower = 1
		case unicode.IsDigit(r):
			digit = 1
		default:
			symbol = 1
		}
	}
	return upper + lower + digit + symbol
}

// containsFold returns whether the value is one of the values, in any case
func containsFold(values []string, value string) bool {
	for _, v := range values {
		if strings.EqualFold(v, value) {
			return true
		}
	}
	return false
}

// setPassword resets the entry's password, which the directory stores
// hashed: an Active Directory user's unicodePwd, which needs ldaps, or by
// the password modify operation (RFC 3062), rather than in an add or a
// modify, which keep it as it's sent
func (manager *Manager) setPassword(ctx context.Context, dn, password string) error {
	object, err := manager.get(ctx, dn, "objectClass")
	if err != nil {
		return err
	}
	activeDirectory := containsFold(object.GetAll("objectClass"), "user")
	if activeDirectory && manager.tls == nil {
		return httpresponse.ErrBadRequest.With("Active Directory passwords need ldaps")
	}
	return ldaperr(manager.write(ctx, func(conn *ldap.Conn) error {
		if activeDirectory {
			return setUnicodePwd(conn, object.DN, "", password)
		}
		_, err := conn.PasswordModify(ldap.NewPasswordModifyRequest(object.DN, "", password))
		return err
	}))
}

// takePassword removes a password, in userPassword or unicodePwd, which has
// a value, from the attributes, and returns it, or empty. One without a
// value is kept, which deletes it in an update. A password has one value.
func takePassword(values url.Values) (string, error) {
	var password string
	count := 0
	for key, value := range values {
		if isPassword(key) && len(value) > 0 {
			password, count = value[0], count+len(value)
			delete(values, key)
		}
	}
	if count > 1 {
		return "", httpresponse.ErrBadRequest.With("A password has one value")
	}
	return password, nil
}

// isPassword returns whether the attribute, in any case, and with options,
// such as userPassword;binary, has a password
func isPassword(name string) bool {
	name, _, _ = strings.Cut(name, ";")
	return strings.EqualFold(name, "userPassword") || strings.EqualFold(name, "unicodePwd")
}

// hidePasswords removes the attributes which have passwords from the
// object, which some directories return, as they were sent
func hidePasswords(object *schema.Object) *schema.Object {
	for key := range object.Values {
		if isPassword(key) {
			delete(object.Values, key)
		}
	}
	return object
}
