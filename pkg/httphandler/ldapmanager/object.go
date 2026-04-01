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
	"io"
	"net/http"
	"net/url"
	"strings"

	// Packages
	ldap "github.com/djthorpe/go-auth/pkg/ldapmanager"
	markdown "github.com/djthorpe/go-auth/pkg/markdown"
	schema "github.com/djthorpe/go-auth/schema/ldap"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func ObjectHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "object", nil, httprequest.NewPathItem(
		"Object operations",
		"Operations on LDAP objects",
		"Object",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listObjects(r.Context(), manager, w, r)
		},
		"List objects",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/object").Body),
		opts.WithQuery(jsonschema.MustFor[schema.ObjectListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.ObjectList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
	)
}

func ObjectResourceHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "object/{dn}", nil, httprequest.NewPathItem(
		"Object operations",
		"Operations on a specific LDAP object",
		"Object",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = getObject(r.Context(), manager, w, r, dn)
		},
		"Get object",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/object/{dn}").Body),
		opts.WithJSONResponse(200, nil),
		opts.WithErrorResponse(400, "Invalid distinguished name."),
		opts.WithErrorResponse(404, "Object not found."),
	).Put(
		func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = createObject(r.Context(), manager, w, r, dn)
		},
		"Create object",
		opts.WithDescription(doc.Section(3, "PUT /{prefix}/object/{dn}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPutRequest]()),
		opts.WithJSONResponse(201, nil),
		opts.WithErrorResponse(400, "Invalid distinguished name or request body."),
		opts.WithErrorResponse(409, "Object already exists."),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = updateObject(r.Context(), manager, w, r, dn)
		},
		"Update object",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/object/{dn}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPutRequest]()),
		opts.WithJSONResponse(200, nil),
		opts.WithErrorResponse(400, "Invalid distinguished name or request body."),
		opts.WithErrorResponse(404, "Object not found."),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = deleteObject(r.Context(), manager, w, r, dn)
		},
		"Delete object",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/object/{dn}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid distinguished name."),
		opts.WithErrorResponse(404, "Object not found."),
	)
}

func ObjectBindHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "object/{dn}/bind", nil, httprequest.NewPathItem(
		"Object bind operations",
		"Authentication operations for a specific LDAP object",
		"Object",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = bindObject(r.Context(), manager, w, r, dn)
		},
		"Bind object",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/object/{dn}/bind").Body),
		opts.WithRequest("text/plain", jsonschema.MustFor[string]()),
		opts.WithJSONResponse(200, nil),
		opts.WithErrorResponse(400, "Invalid distinguished name or request body."),
		opts.WithErrorResponse(401, "Invalid credentials."),
		opts.WithErrorResponse(404, "Object not found."),
	)
}

func ObjectPasswordHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "object/{dn}/password", nil, httprequest.NewPathItem(
		"Object password operations",
		"Password management operations for a specific LDAP object",
		"Object",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			dn, err := objectPathDN(r.PathValue("dn"))
			if err != nil {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
				return
			}
			_ = changePasswordObject(r.Context(), manager, w, r, dn)
		},
		"Change object password",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/object/{dn}/password").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPasswordRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.PasswordResponse]()),
		opts.WithErrorResponse(400, "Invalid distinguished name or request body."),
		opts.WithErrorResponse(401, "Invalid credentials."),
		opts.WithErrorResponse(404, "Object not found."),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listObjects(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	// Decode the query parameters
	var req schema.ObjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	// List objects
	objects, err := manager.List(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	// Return the response
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), objects)
}

func objectPathDN(dn string) (string, error) {
	if dn == "" {
		return "", httpresponse.Err(http.StatusBadRequest).With("dn is required")
	} else if unescaped, err := url.PathUnescape(dn); err != nil {
		return "", httpresponse.Err(http.StatusBadRequest).With(err.Error())
	} else {
		return unescaped, nil
	}
}

func getObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	object, err := manager.Get(ctx, dn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}

func createObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	object, err := manager.Create(ctx, dn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), object)
}

func updateObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	object, err := manager.Update(ctx, dn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}

func bindObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	password, err := io.ReadAll(r.Body)
	if err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	object, err := manager.Bind(ctx, dn, string(password))
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}

func changePasswordObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	var req schema.ObjectPasswordRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	old := strings.TrimSpace(req.Old)
	var newPassword *string
	if req.New != nil {
		if trimmed := strings.TrimSpace(*req.New); trimmed != "" {
			newPassword = &trimmed
		}
	}
	object, generatedPassword, err := manager.ChangePassword(ctx, dn, old, newPassword)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object.WithPassword(generatedPassword))
}

func deleteObject(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, dn string) error {
	object, err := manager.Delete(ctx, dn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), object)
}
