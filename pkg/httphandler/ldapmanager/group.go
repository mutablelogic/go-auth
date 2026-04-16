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
	"net/url"
	"strings"

	// Packages
	ldap "github.com/mutablelogic/go-auth/pkg/ldapmanager"
	markdown "github.com/mutablelogic/go-auth/pkg/markdown"
	schema "github.com/mutablelogic/go-auth/schema/ldap"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func GroupHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "group", nil, httprequest.NewPathItem(
		"Group operations",
		"Operations on LDAP groups",
		"Groups",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = listGroups(r.Context(), manager, w, r)
		},
		"List groups",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/group").Body),
		opts.WithQuery(jsonschema.MustFor[schema.ObjectListRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.ObjectList]()),
		opts.WithErrorResponse(400, "Invalid filter or pagination parameters."),
	)
}

func GroupResourceHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "group/{cn}", nil, httprequest.NewPathItem(
		"Group resource operations",
		"Operations on a specific LDAP group",
		"Groups",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = getGroup(r.Context(), manager, w, r, cn)
		},
		"Get group",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/group/{cn}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid common name."),
		opts.WithErrorResponse(404, "Group not found."),
	).Put(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = createGroup(r.Context(), manager, w, r, cn)
		},
		"Create group",
		opts.WithDescription(doc.Section(3, "PUT /{prefix}/group/{cn}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPutRequest]()),
		opts.WithJSONResponse(201, nil),
		opts.WithErrorResponse(400, "Invalid common name or request body."),
		opts.WithErrorResponse(409, "Group already exists."),
	).Patch(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = updateGroup(r.Context(), manager, w, r, cn)
		},
		"Update group",
		opts.WithDescription(doc.Section(3, "PATCH /{prefix}/group/{cn}").Body),
		opts.WithJSONRequest(jsonschema.MustFor[schema.ObjectPutRequest]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid common name or request body."),
		opts.WithErrorResponse(404, "Group not found."),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = deleteGroup(r.Context(), manager, w, r, cn)
		},
		"Delete group",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/group/{cn}").Body),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid common name."),
		opts.WithErrorResponse(404, "Group not found."),
	)
}

func GroupUserResourceHandler(manager *ldap.Manager, doc *markdown.Document) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "group/{cn}/user", nil, httprequest.NewPathItem(
		"Group membership operations",
		"Operations on users belonging to a specific LDAP group",
		"Groups",
	).Post(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = addGroupUsers(r.Context(), manager, w, r, cn)
		},
		"Add users to group",
		opts.WithDescription(doc.Section(3, "POST /{prefix}/group/{cn}/user").Body),
		opts.WithJSONRequest(jsonschema.MustFor[[]string]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid group name or request body."),
		opts.WithErrorResponse(404, "Group or user not found."),
	).Delete(
		func(w http.ResponseWriter, r *http.Request) {
			cn, err := url.PathUnescape(r.PathValue("cn"))
			if err != nil || cn == "" {
				httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), "invalid cn")
				return
			}
			_ = removeGroupUsers(r.Context(), manager, w, r, cn)
		},
		"Remove users from group",
		opts.WithDescription(doc.Section(3, "DELETE /{prefix}/group/{cn}/user").Body),
		opts.WithJSONRequest(jsonschema.MustFor[[]string]()),
		opts.WithJSONResponse(200, jsonschema.MustFor[schema.Object]()),
		opts.WithErrorResponse(400, "Invalid group name or request body."),
		opts.WithErrorResponse(404, "Group or user not found."),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func listGroups(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request) error {
	var req schema.ObjectListRequest
	if err := httprequest.Query(r.URL.Query(), &req); err != nil {
		return httpresponse.Error(w, httpresponse.ErrBadRequest, err.Error())
	}

	groups, err := manager.ListGroups(ctx, req)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}

	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), groups)
}

func getGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	group, err := manager.GetGroup(ctx, cn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}

func createGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req schema.ObjectPutRequest
	if r.ContentLength != 0 || r.Header.Get("Content-Type") != "" {
		if err := httprequest.Read(r, &req); err != nil {
			if strings.Contains(err.Error(), "Missing request body") {
				req = schema.ObjectPutRequest{}
			} else {
				return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
			}
		}
	}
	group, err := manager.CreateGroup(ctx, cn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusCreated, httprequest.Indent(r), group)
}

func updateGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req schema.ObjectPutRequest
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	group, err := manager.UpdateGroup(ctx, cn, req.Attrs)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}

func deleteGroup(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	group, err := manager.DeleteGroup(ctx, cn)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}

func addGroupUsers(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req []string
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	group, err := manager.AddGroupUsers(ctx, cn, req...)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}

func removeGroupUsers(ctx context.Context, manager *ldap.Manager, w http.ResponseWriter, r *http.Request, cn string) error {
	var req []string
	if err := httprequest.Read(r, &req); err != nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
	}
	group, err := manager.RemoveGroupUsers(ctx, cn, req...)
	if err != nil {
		return httpresponse.Error(w, httpErr(err))
	}
	return httpresponse.JSON(w, http.StatusOK, httprequest.Indent(r), group)
}
