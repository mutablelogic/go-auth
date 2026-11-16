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
	"io"
	"net/url"
	"sort"
	"strings"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

// The filter which matches any entry
const filterAll = "(objectClass=*)"

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// List returns the entries under the base DN which match the request's
// filter, or all of them, with its attributes, or all of them. Count is the
// number which match, and Body those from the offset, up to the limit, or
// schema.MaxListEntries.
func (manager *Manager) List(ctx context.Context, req schema.ObjectListRequest) (_ *schema.ObjectList, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.List", manager.spanAttrs(attribute.String("arg.req", types.Stringify(req)))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	return manager.list(ctx, ldap.ScopeWholeSubtree, manager.dn.String(), req, nil)
}

// Get returns the entry, whose DN is under the base DN, or relative to it
func (manager *Manager) Get(ctx context.Context, dn string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Get", manager.spanAttrs(attribute.String("arg.dn", dn))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.connected(); err != nil {
		return nil, err
	}
	absdn, err := manager.absdn(dn)
	if err != nil {
		return nil, err
	}
	return manager.get(ctx, absdn.String())
}

// Create adds the entry, whose DN is under the base DN, or relative to it,
// with the attributes, which need an objectClass, and returns it
func (manager *Manager) Create(ctx context.Context, dn string, attrs schema.Attrs) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Create", manager.spanAttrs(attribute.String("arg.dn", dn), attrNames(attrs))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.connected(); err != nil {
		return nil, err
	}
	absdn, err := manager.absdn(dn)
	if err != nil {
		return nil, err
	}
	return manager.create(ctx, absdn.String(), url.Values(attrs))
}

// Update replaces the entry's attributes which have values, and deletes
// those which have none, and returns it. Changing a value of the entry's
// RDN renames it first, keeping it under the same parent, then replaces
// the RDN's attribute with all its values, unless the rename has set them.
// When the changes fail, the rename is undone.
func (manager *Manager) Update(ctx context.Context, dn string, attrs schema.Attrs) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Update", manager.spanAttrs(attribute.String("arg.dn", dn), attrNames(attrs))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.connected(); err != nil {
		return nil, err
	}
	absdn, err := manager.absdn(dn)
	if err != nil {
		return nil, err
	}
	return manager.update(ctx, absdn, attrs)
}

// Delete removes the entry, which has no children, and returns it
func (manager *Manager) Delete(ctx context.Context, dn string) (_ *schema.Object, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.Delete", manager.spanAttrs(attribute.String("arg.dn", dn))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	if err := manager.connected(); err != nil {
		return nil, err
	}
	absdn, err := manager.absdn(dn)
	if err != nil {
		return nil, err
	}
	return manager.delete(ctx, absdn.String())
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// update changes the entry at the absolute DN, as Update does
func (manager *Manager) update(ctx context.Context, absdn *schema.DN, attrs schema.Attrs) (*schema.Object, error) {
	values, err := (schema.ObjectPutRequest{Attrs: attrs}).ValidateUpdate()
	if err != nil {
		return nil, auth.HTTPError(err)
	}
	target, rdn, err := renameTarget(absdn, values)
	if err != nil {
		return nil, err
	}

	// Rename, then change the other attributes
	if rdn != "" {
		rename := ldap.NewModifyDNRequest(absdn.String(), rdn, true, "")
		if err := manager.write(ctx, func(conn *ldap.Conn) error { return conn.ModifyDN(rename) }); err != nil {
			return nil, ldaperr(err)
		}
	}
	if err := manager.modify(ctx, target, values); err != nil {
		// Undo the rename, so the entry is as it was, on a new connection,
		// since the manager's can be lost when the context is cancelled
		if rdn != "" {
			undo := ldap.NewModifyDNRequest(target, absdn.RDNs[0].String(), true, "")
			if undoErr := manager.cleanup(ctx, func(conn *ldap.Conn) error { return conn.ModifyDN(undo) }); undoErr != nil {
				return nil, errors.Join(err, httpresponse.ErrInternalError.Withf("%q isn't renamed back: %v", target, ldaperr(undoErr)))
			}
		}
		return nil, err
	}
	return manager.get(ctx, target)
}

// list returns the entries in the scope of the absolute DN which match the
// request's filter, and keep, when it's set, as List does
func (manager *Manager) list(ctx context.Context, scope int, dn string, req schema.ObjectListRequest, keep func(*schema.Object) bool) (*schema.ObjectList, error) {
	limit := listLimit(req.Limit)
	filter := filterAll
	if req.Filter != nil {
		filter = types.Value(req.Filter)
	}

	// Count each entry, and keep those from the offset, up to the limit
	var list schema.ObjectList
	if err := manager.search(ctx, scope, dn, filter, 0, func(entry *schema.Object) error {
		if keep != nil && !keep(entry) {
			return nil
		}
		if list.Count >= req.Offset && list.Count < req.Offset+limit {
			list.Body = append(list.Body, entry)
		}
		list.Count++
		return nil
	}, req.Attr...); err != nil {
		return nil, err
	}
	return &list, nil
}

// delete removes the entry at the absolute DN, and returns it
func (manager *Manager) delete(ctx context.Context, dn string) (*schema.Object, error) {
	object, err := manager.get(ctx, dn)
	if err != nil {
		return nil, err
	}
	if err := manager.write(ctx, func(conn *ldap.Conn) error { return conn.Del(ldap.NewDelRequest(object.DN, nil)) }); err != nil {
		return nil, ldaperr(err)
	}
	return object, nil
}

// connected returns an error when the manager isn't connected
func (manager *Manager) connected() error {
	if manager.conn == nil {
		return httpresponse.ErrGatewayError.With("Not connected")
	}
	return nil
}

// get returns the entry at the DN, or a not found error
func (manager *Manager) get(ctx context.Context, dn string, attrs ...string) (*schema.Object, error) {
	var result *schema.Object
	if err := manager.search(ctx, ldap.ScopeBaseObject, dn, filterAll, 1, func(entry *schema.Object) error {
		result = entry
		return io.EOF
	}, attrs...); err != nil {
		return nil, err
	}
	if result == nil {
		return nil, httpresponse.ErrNotFound.Withf("%q not found", dn)
	}
	return result, nil
}

// search calls the function for each entry which matches the filter, in
// pages, or, when max isn't zero, up to max entries, until the function
// returns io.EOF, or another error, which is returned
func (manager *Manager) search(ctx context.Context, scope int, dn, filter string, max int, fn func(*schema.Object) error, attrs ...string) error {
	if err := manager.connected(); err != nil {
		return err
	}

	// Stop the search when the function does
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	var controls []ldap.Control
	paging := ldap.NewControlPaging(schema.MaxListPaging)
	if max == 0 {
		controls = []ldap.Control{paging}
	}
	req := ldap.NewSearchRequest(dn, scope, ldap.NeverDerefAliases, max, 0, false, filter, attrs, controls)
	for {
		r := manager.conn.SearchAsync(ctx, req, 0)
		for r.Next() {
			if entry := r.Entry(); entry != nil {
				if err := fn(schema.NewObjectFromEntry(entry)); errors.Is(err, io.EOF) {
					return nil
				} else if err != nil {
					return err
				}
			}
		}
		if err := r.Err(); err != nil {
			return ldaperr(err)
		}

		// The next page, when there is one
		resp, ok := ldap.FindControl(r.Controls(), ldap.ControlTypePaging).(*ldap.ControlPaging)
		if !ok || len(resp.Cookie) == 0 {
			return nil
		}
		paging.SetCookie(resp.Cookie)
	}
}

// spanAttrs are the directory's attributes, and others
func (manager *Manager) spanAttrs(attrs ...attribute.KeyValue) []attribute.KeyValue {
	return append(manager.serverAttrs(), attrs...)
}

// attrNames is a span's attribute of the names of the attributes, but not
// their values, which can be passwords
func attrNames(attrs schema.Attrs) attribute.KeyValue {
	names := make([]string, 0, len(attrs))
	for name := range attrs {
		names = append(names, name)
	}
	sort.Strings(names)
	return attribute.StringSlice("arg.attrs", names)
}

// renameTarget returns the DN the entry has after the update, and its new
// RDN, when a value of the RDN changes, or empty, when it doesn't. An RDN's
// attribute can't be deleted.
func renameTarget(dn *schema.DN, attrs url.Values) (string, string, error) {
	if dn == nil || len(dn.RDNs) == 0 || dn.RDNs[0] == nil || len(dn.RDNs[0].Attributes) == 0 {
		return "", "", httpresponse.ErrBadRequest.With("dn is required")
	}

	rdn := &ldap.RelativeDN{}
	rename := false
	for _, attr := range dn.RDNs[0].Attributes {
		if attr == nil {
			continue
		}
		value := attr.Value
		if values, ok := attrValues(attrs, attr.Type); ok {
			if len(values) == 0 {
				return "", "", httpresponse.ErrBadRequest.Withf("naming attribute %q can't be deleted", attr.Type)
			}
			value = values[0]
		}
		rename = rename || value != attr.Value
		rdn.Attributes = append(rdn.Attributes, &ldap.AttributeTypeAndValue{Type: attr.Type, Value: value})
	}
	if !rename {
		return dn.String(), "", nil
	}

	// The new RDN, under the same parent
	target := rdn.String()
	if len(dn.RDNs) > 1 {
		target += "," + (&schema.DN{RDNs: dn.RDNs[1:]}).String()
	}
	return target, rdn.String(), nil
}

// modify replaces the entry's attributes with values, and deletes those
// without, other than those of its RDN which are done
func (manager *Manager) modify(ctx context.Context, dn string, attrs url.Values) error {
	skip, err := manager.rdnDone(ctx, dn, attrs)
	if err != nil {
		return err
	}
	if modify := modifyRequest(dn, attrs, skip); len(modify.Changes) > 0 {
		if err := manager.write(ctx, func(conn *ldap.Conn) error { return conn.Modify(modify) }); err != nil {
			return ldaperr(err)
		}
	}
	return nil
}

// rdnDone returns the attributes of the entry's RDN which the update sets
// to the RDN's value alone, and which the entry has alone, so a rename has
// set them, or they're unchanged. They're left out of the modify request,
// since Active Directory refuses to modify them, even to the same value.
func (manager *Manager) rdnDone(ctx context.Context, dn string, attrs url.Values) (map[string]bool, error) {
	target, err := schema.NewDN(dn)
	if err != nil {
		return nil, httpresponse.ErrBadRequest.Withf("Invalid DN: %v", err)
	}

	// The RDN's attributes which the update has
	rdn := map[string]string{}
	names := []string{}
	for _, attr := range target.RDNs[0].Attributes {
		if _, ok := attrValues(attrs, attr.Type); ok {
			rdn[strings.ToLower(attr.Type)] = attr.Value
			names = append(names, attr.Type)
		}
	}
	if len(names) == 0 {
		return nil, nil
	}

	// Those which are the RDN's value alone, in the update and the entry
	current, err := manager.get(ctx, dn, names...)
	if err != nil {
		return nil, err
	}
	skip := map[string]bool{}
	for _, name := range names {
		value := rdn[strings.ToLower(name)]
		requested, _ := attrValues(attrs, name)
		existing := current.GetAll(name)
		if len(requested) == 1 && requested[0] == value && len(existing) == 1 && strings.EqualFold(existing[0], value) {
			skip[strings.ToLower(name)] = true
		}
	}
	return skip, nil
}

// modifyRequest replaces the attributes with values, and deletes those
// without, other than those to skip, in any case
func modifyRequest(dn string, attrs url.Values, skip map[string]bool) *ldap.ModifyRequest {
	// In a fixed order
	keys := make([]string, 0, len(attrs))
	for key := range attrs {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	modify := ldap.NewModifyRequest(dn, nil)
	for _, key := range keys {
		if skip[strings.ToLower(key)] {
			continue
		}
		if values := attrs[key]; len(values) == 0 {
			modify.Delete(key, nil)
		} else {
			modify.Replace(key, values)
		}
	}
	return modify
}

// attrValues returns the values of the attribute, whose name is in any
// case, and whether it's there
func attrValues(attrs url.Values, name string) ([]string, bool) {
	for key, values := range attrs {
		if strings.EqualFold(key, name) {
			return values, true
		}
	}
	return nil, false
}
