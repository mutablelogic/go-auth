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
	"io"
	"net/http"
	"strings"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) ListObjects(ctx context.Context, req schema.ObjectListRequest) (*schema.ObjectList, error) {
	var response schema.ObjectList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("object"), client.OptQuery(req.Query())); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) GetObject(ctx context.Context, dn string) (*schema.Object, error) {
	var response schema.Object
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("object", dn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) CreateObject(ctx context.Context, dn string, req schema.ObjectPutRequest) (*schema.Object, error) {
	var response schema.Object
	body, err := client.NewJSONRequestEx(http.MethodPut, req, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("object", dn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) UpdateObject(ctx context.Context, dn string, req schema.ObjectPutRequest) (*schema.Object, error) {
	var response schema.Object
	body, err := client.NewJSONRequestEx(http.MethodPatch, req, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("object", dn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) BindObject(ctx context.Context, dn, password string) (*schema.Object, error) {
	var response schema.Object
	body := newTextRequest(http.MethodPost, password, types.ContentTypeJSON)
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("object", dn, "bind")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) ChangeObjectPassword(ctx context.Context, dn string, req schema.ObjectPasswordRequest) (*schema.PasswordResponse, error) {
	var response schema.PasswordResponse
	body, err := client.NewJSONRequestEx(http.MethodPost, req, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if err := c.DoWithContext(ctx, body, &response, client.OptPath("object", dn, "password")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) DeleteObject(ctx context.Context, dn string) (*schema.Object, error) {
	var response schema.Object
	if err := c.DoWithContext(ctx, client.MethodDelete, &response, client.OptPath("object", dn)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

///////////////////////////////////////////////////////////////////////////////
// PASSWORD PAYLOAD

type textRequest struct {
	method string
	accept string
	reader *strings.Reader
}

func newTextRequest(method, body, accept string) client.Payload {
	return &textRequest{method: method, accept: accept, reader: strings.NewReader(body)}
}

func (req *textRequest) Method() string { return req.method }

func (req *textRequest) Accept() string {
	if req.accept == "" {
		return client.ContentTypeAny
	}
	return req.accept
}

func (req *textRequest) Type() string {
	return client.ContentTypeTextPlain
}

func (req *textRequest) Read(b []byte) (int, error) {
	if req.reader == nil {
		return 0, io.EOF
	}
	return req.reader.Read(b)
}
