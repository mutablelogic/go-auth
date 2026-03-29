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
	"log/slog"
	"strings"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	ldap "github.com/go-ldap/ldap/v3"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - OBJECT CLASSES AND ATTRIBUTES

// Returns object classes
func (manager *Manager) ListObjectClasses(ctx context.Context, req schema.ObjectClassListRequest) (*schema.ObjectClassListResponse, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	subschemadn, err := manager.subschemaDN(ctx)
	if err != nil {
		return nil, err
	}

	// List the object classes
	var response schema.ObjectClassListResponse
	limit := uint64(schema.MaxListEntries)
	if req.Limit != nil {
		limit = min(types.Value(req.Limit), limit)
	}
	if err := manager.listSchemaValues(ctx, subschemadn, schema.AttrObjectClasses, func(values []string) error {
		for _, objectClass := range parseObjectClasses(values) {
			if objectClass == nil || !objectClass.Matches(req) {
				continue
			}
			if response.Count >= req.Offset && response.Count < req.Offset+limit {
				response.Body = append(response.Body, objectClass)
			}
			response.Count++
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Return success
	return &response, nil
}

// Returns attribute types
func (manager *Manager) ListAttributeTypes(ctx context.Context, req schema.AttributeTypeListRequest) (*schema.AttributeTypeListResponse, error) {
	manager.Lock()
	defer manager.Unlock()

	// Check connection
	if manager.conn == nil {
		return nil, httpresponse.ErrGatewayError.With("Not connected")
	}

	subschemadn, err := manager.subschemaDN(ctx)
	if err != nil {
		return nil, err
	}

	// List the attribute types
	var response schema.AttributeTypeListResponse
	limit := uint64(schema.MaxListEntries)
	if req.Limit != nil {
		limit = min(types.Value(req.Limit), limit)
	}
	if err := manager.listSchemaValues(ctx, subschemadn, schema.AttrAttributeTypes, func(values []string) error {
		for _, attributeType := range parseAttributeTypes(values) {
			if attributeType == nil || !attributeType.Matches(req) {
				continue
			}
			if response.Count >= req.Offset && response.Count < req.Offset+limit {
				response.Body = append(response.Body, attributeType)
			}
			response.Count++
		}
		return nil
	}); err != nil {
		return nil, err
	}

	// Return success
	return &response, nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (manager *Manager) subschemaDN(ctx context.Context) (string, error) {
	root, err := manager.get(ctx, ldap.ScopeBaseObject, "", "(objectclass=*)", schema.AttrSubSchemaDN)
	if err != nil {
		return "", err
	}
	return subschemaDNFromRoot(root)
}

func subschemaDNFromRoot(root *schema.Object) (string, error) {
	if root == nil {
		return "", httpresponse.ErrNotFound.With("rootDSE not found")
	}
	subschemadn := root.Get(schema.AttrSubSchemaDN)
	if subschemadn == nil || strings.TrimSpace(*subschemadn) == "" {
		return "", httpresponse.ErrNotFound.With(schema.AttrSubSchemaDN, " not found")
	}
	return *subschemadn, nil
}

func (manager *Manager) listSchemaValues(ctx context.Context, subschemadn, attr string, fn func([]string) error) error {
	return manager.list(ctx, ldap.ScopeBaseObject, subschemadn, "(objectclass=subschema)", 1, func(entry *schema.Object) error {
		if entry == nil {
			return httpresponse.ErrNotFound.With("subschema entry not found")
		}
		values := entry.GetAll(attr)
		if values == nil {
			return httpresponse.ErrInternalError.With(attr, " not found")
		}
		return fn(values)
	}, attr)
}

func (manager *Manager) discoverObjectClasses(ctx context.Context) (map[string]*schema.ObjectClass, error) {
	subschemadn, err := manager.subschemaDN(ctx)
	if err != nil {
		return nil, err
	}

	classes := make(map[string]*schema.ObjectClass)
	if err := manager.listSchemaValues(ctx, subschemadn, schema.AttrObjectClasses, func(values []string) error {
		for _, oc := range parseObjectClasses(values) {
			if oc == nil {
				continue
			}
			for _, name := range oc.Name {
				classes[strings.ToLower(name)] = oc
			}
		}
		return nil
	}); err != nil {
		return nil, err
	}
	return classes, nil
}

func selectDiscoveredClasses(classes map[string]*schema.ObjectClass, structural, auxiliary []string) []string {

	var result []string
	for _, known := range structural {
		oc := classes[strings.ToLower(known)]
		if oc == nil {
			continue
		}
		if strings.EqualFold(string(oc.ClassKind), string(schema.ObjectClassKindStructural)) {
			result = append(result, known)
			break
		}
	}

	for _, known := range auxiliary {
		oc := classes[strings.ToLower(known)]
		if oc != nil && strings.EqualFold(string(oc.ClassKind), string(schema.ObjectClassKindAuxiliary)) {
			result = append(result, known)
		}
	}

	return result
}

// discoverGroupClasses queries the subschema and returns a compatible set of
// group classes for new entries: one structural class plus optional auxiliary
// classes such as posixGroup when the server supports them.
// The manager lock MUST be held by the caller.
func (manager *Manager) discoverGroupClasses(ctx context.Context) ([]string, error) {
	classes, err := manager.discoverObjectClasses(ctx)
	if err != nil {
		return nil, err
	}
	result := selectDiscoveredClasses(classes, schema.WellKnownGroupClasses, []string{"posixGroup"})
	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

// discoverUserClasses queries the subschema and returns a compatible set of
// user classes for new entries: one structural class plus optional auxiliary
// classes such as posixAccount when the server supports them.
// The manager lock MUST be held by the caller.
func (manager *Manager) discoverUserClasses(ctx context.Context) ([]string, error) {
	classes, err := manager.discoverObjectClasses(ctx)
	if err != nil {
		return nil, err
	}
	result := selectDiscoveredClasses(classes, schema.WellKnownUserClasses, schema.WellKnownUserAuxiliaryClasses)

	if len(result) == 0 {
		return nil, nil
	}
	return result, nil
}

func (manager *Manager) discoverSchemas(ctx context.Context, logger *slog.Logger) {
	manager.Lock()
	defer manager.Unlock()

	if manager.groups != nil && len(manager.groups.ObjectClass) == 0 {
		classes, err := manager.discoverGroupClasses(ctx)
		if err != nil || len(classes) == 0 {
			classes = schema.DefaultGroupObjectClasses
		}
		manager.groups.ObjectClass = classes
		if logger != nil {
			logger.Debug("group schema", "dn", manager.groups.DN.String(), "classes", manager.groups.ObjectClass)
		}
	}

	if manager.users != nil && len(manager.users.ObjectClass) == 0 {
		classes, err := manager.discoverUserClasses(ctx)
		if err != nil || len(classes) == 0 {
			classes = schema.DefaultUserObjectClasses
		}
		manager.users.ObjectClass = classes
		if logger != nil {
			logger.Debug("user schema", "dn", manager.users.DN.String(), "classes", manager.users.ObjectClass)
		}
	}
}

func parseObjectClasses(values []string) []*schema.ObjectClass {
	result := make([]*schema.ObjectClass, 0, len(values))
	for _, value := range values {
		if objectClass, err := schema.ParseObjectClass(value); err == nil && objectClass != nil {
			result = append(result, objectClass)
		}
	}
	return result
}

func parseAttributeTypes(values []string) []*schema.AttributeType {
	result := make([]*schema.AttributeType, 0, len(values))
	for _, value := range values {
		if attributeType, err := schema.ParseAttributeType(value); err == nil && attributeType != nil {
			result = append(result, attributeType)
		}
	}
	return result
}
