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
	"github.com/djthorpe/go-auth/pkg/markdown"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	schemadef "github.com/djthorpe/go-auth/schema/ldapparser"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ClassHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "class", nil, httprequest.NewPathItem(
		"Object class operations",
		"Operations on LDAP object classes",
		"Object Schema",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			if err := listClasses(r.Context(), manager, w, r); err != nil {
				httpresponse.Error(w, httpErr(err))
			}
		},
		"List object classes",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/class").Body),
		opts.WithQuery(jsonschema.MustFor[schema.ObjectClassListRequest]()),
		opts.WithJSONResponse(200, objectClassListResponseSchema()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
	)
}

func AttrHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "attr", nil, httprequest.NewPathItem(
		"Attribute type operations",
		"Operations on LDAP attribute types",
		"Object Schema",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			if err := listAttributes(r.Context(), manager, w, r); err != nil {
				httpresponse.Error(w, httpErr(err))
			}
		},
		"List attribute types",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/attr").Body),
		opts.WithQuery(jsonschema.MustFor[schema.AttributeTypeListRequest]()),
		opts.WithJSONResponse(200, attributeTypeListResponseSchema()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

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
