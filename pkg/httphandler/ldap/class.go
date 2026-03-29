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
	"net/http"

	// Packages
	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	schemadef "github.com/djthorpe/go-auth/schema/ldapparser"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ClassHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "class", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listClasses(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Object class operations",
			Description: "Operations on LDAP object classes",
			Get: &openapi.Operation{
				Tags:        []string{"Object Schema"},
				Summary:     "List object classes",
				Description: "Returns a filtered list of LDAP object classes from the subschema entry.",
				Parameters: []openapi.Parameter{
					{Name: "filter", In: openapi.ParameterInQuery, Description: "Exact class name or OID match. Class names are matched case-insensitively.", Schema: jsonschema.MustFor[string]()},
					{Name: "kind", In: openapi.ParameterInQuery, Description: "Object class kind.", Schema: objectClassKindParameterSchema()},
					{Name: "superior", In: openapi.ParameterInQuery, Description: "Required superior classes. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "must", In: openapi.ParameterInQuery, Description: "Required MUST attributes. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "may", In: openapi.ParameterInQuery, Description: "Required MAY attributes. May be repeated.", Schema: jsonschema.MustFor[[]string]()},
					{Name: "obsolete", In: openapi.ParameterInQuery, Description: "Filter obsolete classes.", Schema: jsonschema.MustFor[bool]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of classes to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Object class list.", Content: map[string]openapi.MediaType{"application/json": {Schema: objectClassListResponseSchema()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

func AttrHandler(manager *ldap.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "attr", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = listAttributes(r.Context(), manager, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Attribute type operations",
			Description: "Operations on LDAP attribute types",
			Get: &openapi.Operation{
				Tags:        []string{"Object Schema"},
				Summary:     "List attribute types",
				Description: "Returns a filtered list of LDAP attribute types from the subschema entry.",
				Parameters: []openapi.Parameter{
					{Name: "filter", In: openapi.ParameterInQuery, Description: "Exact attribute name or OID match. Names are matched case-insensitively.", Schema: jsonschema.MustFor[string]()},
					{Name: "usage", In: openapi.ParameterInQuery, Description: "Attribute usage.", Schema: attributeUsageParameterSchema()},
					{Name: "superior", In: openapi.ParameterInQuery, Description: "Required superior attribute type.", Schema: jsonschema.MustFor[string]()},
					{Name: "obsolete", In: openapi.ParameterInQuery, Description: "Filter obsolete attribute types.", Schema: jsonschema.MustFor[bool]()},
					{Name: "singleValue", In: openapi.ParameterInQuery, Description: "Filter single-value attribute types.", Schema: jsonschema.MustFor[bool]()},
					{Name: "collective", In: openapi.ParameterInQuery, Description: "Filter collective attribute types.", Schema: jsonschema.MustFor[bool]()},
					{Name: "noUserModification", In: openapi.ParameterInQuery, Description: "Filter non-user-modifiable attribute types.", Schema: jsonschema.MustFor[bool]()},
					{Name: "offset", In: openapi.ParameterInQuery, Description: "Pagination offset.", Schema: jsonschema.MustFor[uint64]()},
					{Name: "limit", In: openapi.ParameterInQuery, Description: "Maximum number of attribute types to return.", Schema: jsonschema.MustFor[uint64]()},
				},
				Responses: map[string]openapi.Response{
					"200": {Description: "Attribute type list.", Content: map[string]openapi.MediaType{"application/json": {Schema: attributeTypeListResponseSchema()}}},
					"400": {Description: "Invalid filter or pagination parameters."},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func objectClassKindParameterSchema() *jsonschema.Schema {
	base := jsonschema.MustFor[string]()
	paramSchema := *base
	paramSchema.Enum = []any{
		schema.ObjectClassKindAbstract.String(),
		schema.ObjectClassKindStructural.String(),
		schema.ObjectClassKindAuxiliary.String(),
	}
	return &paramSchema
}

func attributeUsageParameterSchema() *jsonschema.Schema {
	base := jsonschema.MustFor[string]()
	paramSchema := *base
	paramSchema.Enum = []any{
		schema.AttributeUsageUserApplications.String(),
		schema.AttributeUsageDirectoryOperation.String(),
		schema.AttributeUsageDistributedOperation.String(),
		schema.AttributeUsageDSAOperation.String(),
	}
	return &paramSchema
}

func objectClassListResponseSchema() *jsonschema.Schema {
	responseSchema := jsonschema.MustFor[schema.ObjectClassListResponse]()
	if body := responseSchema.Properties["body"]; body != nil {
		body.Items = &jsonschema.MustFor[schemadef.ObjectClassSchema]().Schema
	}
	return responseSchema
}

func attributeTypeListResponseSchema() *jsonschema.Schema {
	responseSchema := jsonschema.MustFor[schema.AttributeTypeListResponse]()
	if body := responseSchema.Properties["body"]; body != nil {
		body.Items = &jsonschema.MustFor[schemadef.AttributeTypeSchema]().Schema
	}
	return responseSchema
}

func listClasses(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.ObjectClassListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	classes, err := manager.ListObjectClasses(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), classes)
}

func listAttributes(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.AttributeTypeListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	attrs, err := manager.ListAttributeTypes(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), attrs)
}
