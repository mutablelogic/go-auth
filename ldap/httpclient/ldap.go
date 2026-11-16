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

package httpclient

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SCHEMA

// ListObjectClasses returns the directory's object classes, by name, which
// match the request
func (c *Client) ListObjectClasses(ctx context.Context, req schema.ObjectClassListRequest) (*schema.ObjectClassListResponse, error) {
	return get[schema.ObjectClassListResponse](ctx, c, req, "class")
}

// ListAttributeTypes returns the directory's attribute types, by name,
// which match the request
func (c *Client) ListAttributeTypes(ctx context.Context, req schema.AttributeTypeListRequest) (*schema.AttributeTypeListResponse, error) {
	return get[schema.AttributeTypeListResponse](ctx, c, req, "attr")
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - USERS

// ListUsers returns the users, or a group's members, which match the
// request
func (c *Client) ListUsers(ctx context.Context, req schema.UserListRequest) (*schema.ObjectList, error) {
	return get[schema.ObjectList](ctx, c, req, "user")
}

// GetUser returns the user with the name
func (c *Client) GetUser(ctx context.Context, name string) (*schema.Object, error) {
	return get[schema.Object](ctx, c, nil, "user", name)
}

// CreateUser creates a user with the name, and the attributes, which can
// be none. With allocateGID, its gidNumber is its uidNumber.
func (c *Client) CreateUser(ctx context.Context, name string, attrs schema.Attrs, allocateGID bool) (*schema.Object, error) {
	var opts []client.RequestOpt
	if allocateGID {
		opts = append(opts, client.OptQuery(url.Values{"allocate_gid": {strconv.FormatBool(allocateGID)}}))
	}
	return send[schema.Object](ctx, c, http.MethodPut, schema.ObjectPutRequest{Attrs: attrs}, opts, "user", name)
}

// UpdateUser replaces the user's attributes which have values, and deletes
// those which have none. Changing its name renames it.
func (c *Client) UpdateUser(ctx context.Context, name string, attrs schema.Attrs) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodPatch, schema.ObjectPutRequest{Attrs: attrs}, nil, "user", name)
}

// DeleteUser deletes the user, and returns it, as it was
func (c *Client) DeleteUser(ctx context.Context, name string) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodDelete, nil, nil, "user", name)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - GROUPS

// ListGroups returns the groups, or a user's, which match the request
func (c *Client) ListGroups(ctx context.Context, req schema.GroupListRequest) (*schema.ObjectList, error) {
	return get[schema.ObjectList](ctx, c, req, "group")
}

// GetGroup returns the group with the name
func (c *Client) GetGroup(ctx context.Context, name string) (*schema.Object, error) {
	return get[schema.Object](ctx, c, nil, "group", name)
}

// CreateGroup creates a group with the name, and the attributes, which can
// be none
func (c *Client) CreateGroup(ctx context.Context, name string, attrs schema.Attrs) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodPut, schema.ObjectPutRequest{Attrs: attrs}, nil, "group", name)
}

// UpdateGroup replaces the group's attributes which have values, and
// deletes those which have none. Changing its cn renames it.
func (c *Client) UpdateGroup(ctx context.Context, name string, attrs schema.Attrs) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodPatch, schema.ObjectPutRequest{Attrs: attrs}, nil, "group", name)
}

// DeleteGroup deletes the group, and returns it, as it was
func (c *Client) DeleteGroup(ctx context.Context, name string) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodDelete, nil, nil, "group", name)
}

// AddGroupUsers adds the users, by name, to the group, and returns it
func (c *Client) AddGroupUsers(ctx context.Context, group string, users ...string) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodPost, nonNil(users), nil, "group", group, "user")
}

// RemoveGroupUsers removes the users, by name, from the group, and returns
// it
func (c *Client) RemoveGroupUsers(ctx context.Context, group string, users ...string) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodDelete, nonNil(users), nil, "group", group, "user")
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - OBJECTS

// ListObjects returns the entries under the base DN, or the prefix, which
// match the request
func (c *Client) ListObjects(ctx context.Context, req schema.ObjectListRequest) (*schema.ObjectList, error) {
	return get[schema.ObjectList](ctx, c, req, "object")
}

// GetObject returns the entry, whose DN is under the base DN, or relative
// to it
func (c *Client) GetObject(ctx context.Context, dn string) (*schema.Object, error) {
	return get[schema.Object](ctx, c, nil, "object", dn)
}

// CreateObject creates the entry, with the attributes, which need an
// objectClass
func (c *Client) CreateObject(ctx context.Context, dn string, attrs schema.Attrs) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodPut, schema.ObjectPutRequest{Attrs: attrs}, nil, "object", dn)
}

// UpdateObject replaces the entry's attributes which have values, and
// deletes those which have none. Changing a value of its RDN renames it.
func (c *Client) UpdateObject(ctx context.Context, dn string, attrs schema.Attrs) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodPatch, schema.ObjectPutRequest{Attrs: attrs}, nil, "object", dn)
}

// DeleteObject deletes the entry, which has no children, and returns it,
// as it was
func (c *Client) DeleteObject(ctx context.Context, dn string) (*schema.Object, error) {
	return send[schema.Object](ctx, c, http.MethodDelete, nil, nil, "object", dn)
}

// BindObject checks the entry's password, and returns the entry, or
// auth.ErrInvalidProvider, when it's wrong
func (c *Client) BindObject(ctx context.Context, dn, password string) (*schema.Object, error) {
	var response schema.Object
	req := textRequest{Reader: strings.NewReader(password), method: http.MethodPost}
	if err := c.DoWithContext(ctx, req, &response, client.OptPath(pathLDAP, "object", dn, "bind")); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// ChangeObjectPassword changes the entry's password, with the old one, or
// resets it, without, and returns the entry, with the password, when it's
// generated
func (c *Client) ChangeObjectPassword(ctx context.Context, dn string, req schema.ObjectPasswordRequest) (*schema.PasswordResponse, error) {
	return send[schema.PasswordResponse](ctx, c, http.MethodPost, req, nil, "object", dn, "password")
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// nonNil returns the users, or an empty list, which is sent as [], rather
// than null
func nonNil(users []string) []string {
	if users == nil {
		return []string{}
	}
	return users
}
