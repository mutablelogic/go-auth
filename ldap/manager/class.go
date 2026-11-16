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
	"sort"
	"strings"

	// Packages
	ldap "github.com/go-ldap/ldap/v3"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// subschema is the directory's object classes and attribute types, sorted
// by name, as they were when the connection read them
type subschema struct {
	conn       *ldap.Conn
	classes    []*schema.ObjectClass
	attributes []*schema.AttributeType
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ListObjectClasses returns copies of the directory's object classes, by
// name, which match the request. Count is the number which match, and Body those from
// the offset, up to the limit, or schema.MaxListEntries.
func (manager *Manager) ListObjectClasses(ctx context.Context, req schema.ObjectClassListRequest) (_ *schema.ObjectClassListResponse, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.ListObjectClasses", manager.spanAttrs(attribute.String("arg.req", types.Stringify(req)))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	subschema, err := manager.subschema(ctx)
	if err != nil {
		return nil, err
	}

	var response schema.ObjectClassListResponse
	limit := listLimit(req.Limit)
	for _, class := range subschema.classes {
		if !class.Matches(req) {
			continue
		}
		if response.Count >= req.Offset && response.Count < req.Offset+limit {
			response.Body = append(response.Body, class.Clone())
		}
		response.Count++
	}
	return &response, nil
}

// ListAttributeTypes returns copies of the directory's attribute types, by
// name, which match the request. Count is the number which match, and Body those
// from the offset, up to the limit, or schema.MaxListEntries.
func (manager *Manager) ListAttributeTypes(ctx context.Context, req schema.AttributeTypeListRequest) (_ *schema.AttributeTypeListResponse, err error) {
	ctx, endSpan := otel.StartSpan(manager.tracer, ctx, "ldapmanager.ListAttributeTypes", manager.spanAttrs(attribute.String("arg.req", types.Stringify(req)))...)
	defer func() { endSpan(err) }()

	manager.mu.Lock()
	defer manager.mu.Unlock()
	subschema, err := manager.subschema(ctx)
	if err != nil {
		return nil, err
	}

	var response schema.AttributeTypeListResponse
	limit := listLimit(req.Limit)
	for _, attr := range subschema.attributes {
		if !attr.Matches(req) {
			continue
		}
		if response.Count >= req.Offset && response.Count < req.Offset+limit {
			response.Body = append(response.Body, attr.Clone())
		}
		response.Count++
	}
	return &response, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// subschema returns the directory's schema, which is read once for each
// connection, as the rootDSE's subschemaSubentry has it. Definitions which
// don't parse are left out.
func (manager *Manager) subschema(ctx context.Context) (*subschema, error) {
	if err := manager.connected(); err != nil {
		return nil, err
	}
	if manager.schema != nil && manager.schema.conn == manager.conn {
		return manager.schema, nil
	}

	// The rootDSE has the DN of the subschema entry
	root, err := manager.get(ctx, "", schema.AttrSubSchemaDN)
	if err != nil {
		return nil, err
	}
	dn := root.Get(schema.AttrSubSchemaDN)
	if dn == nil || strings.TrimSpace(*dn) == "" {
		return nil, httpresponse.ErrNotFound.With("The directory has no ", schema.AttrSubSchemaDN)
	}
	entry, err := manager.get(ctx, *dn, schema.AttrObjectClasses, schema.AttrAttributeTypes)
	if err != nil {
		return nil, err
	}

	result := &subschema{
		conn:       manager.conn,
		classes:    parseObjectClasses(entry.GetAll(schema.AttrObjectClasses)),
		attributes: parseAttributeTypes(entry.GetAll(schema.AttrAttributeTypes)),
	}
	manager.schema = result
	return result, nil
}

// parseObjectClasses returns the object classes which parse, by name
func parseObjectClasses(values []string) []*schema.ObjectClass {
	result := make([]*schema.ObjectClass, 0, len(values))
	for _, value := range values {
		if class, err := schema.ParseObjectClass(value); err == nil {
			result = append(result, class)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return strings.ToLower(result[i].Identifier()) < strings.ToLower(result[j].Identifier())
	})
	return result
}

// parseAttributeTypes returns the attribute types which parse, by name
func parseAttributeTypes(values []string) []*schema.AttributeType {
	result := make([]*schema.AttributeType, 0, len(values))
	for _, value := range values {
		if attr, err := schema.ParseAttributeType(value); err == nil {
			result = append(result, attr)
		}
	}
	sort.SliceStable(result, func(i, j int) bool {
		return strings.ToLower(result[i].Identifier()) < strings.ToLower(result[j].Identifier())
	})
	return result
}

// listLimit returns the limit, up to schema.MaxListEntries
func listLimit(limit *uint64) uint64 {
	if limit == nil {
		return schema.MaxListEntries
	}
	return min(*limit, schema.MaxListEntries)
}
