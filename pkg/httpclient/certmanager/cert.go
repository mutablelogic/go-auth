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

package certmanager

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/cert"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (c *Client) CreateCert(ctx context.Context, req schema.CreateCertRequest, ca schema.CertKey) (*schema.Cert, error) {
	var response schema.Cert
	body, err := client.NewJSONRequestEx(http.MethodPost, req, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if serial := strings.TrimSpace(ca.Serial); serial != "" {
		if err := c.DoWithContext(ctx, body, &response, client.OptPath("cert", ca.Name, serial)); err != nil {
			return nil, err
		}
	} else if err := c.DoWithContext(ctx, body, &response, client.OptPath("cert", ca.Name)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) RenewCert(ctx context.Context, cert schema.CertKey, req schema.RenewCertRequest) (*schema.Cert, error) {
	var response schema.Cert
	body, err := client.NewJSONRequestEx(http.MethodPost, renewRequestBody(req), types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if serial := strings.TrimSpace(cert.Serial); serial != "" {
		if err := c.DoWithContext(ctx, body, &response, client.OptPath("cert", cert.Name, serial, "renew")); err != nil {
			return nil, err
		}
	} else if err := c.DoWithContext(ctx, body, &response, client.OptPath("cert", cert.Name, "renew")); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) GetCert(ctx context.Context, cert schema.CertKey, chain, private bool) (*schema.CertBundle, error) {
	var response schema.CertBundle
	query := certGetQuery(chain, private)
	if serial := strings.TrimSpace(cert.Serial); serial != "" {
		if err := c.DoWithContext(ctx, nil, &response, client.OptPath("cert", cert.Name, serial), client.OptQuery(query)); err != nil {
			return nil, err
		}
	} else if err := c.DoWithContext(ctx, nil, &response, client.OptPath("cert", cert.Name), client.OptQuery(query)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) UpdateCert(ctx context.Context, cert schema.CertKey, meta schema.CertMeta) (*schema.Cert, error) {
	var response schema.Cert
	body := make(map[string]any)
	if meta.Enabled != nil {
		body["enabled"] = types.Value(meta.Enabled)
	}
	if meta.Tags != nil {
		if len(meta.Tags) == 0 {
			body["tags"] = []string{}
		} else {
			body["tags"] = append([]string(nil), meta.Tags...)
		}
	}
	req, err := client.NewJSONRequestEx(http.MethodPatch, body, types.ContentTypeJSON)
	if err != nil {
		return nil, err
	}
	if serial := strings.TrimSpace(cert.Serial); serial != "" {
		if err := c.DoWithContext(ctx, req, &response, client.OptPath("cert", cert.Name, serial)); err != nil {
			return nil, err
		}
	} else if err := c.DoWithContext(ctx, req, &response, client.OptPath("cert", cert.Name)); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

func (c *Client) ListCerts(ctx context.Context, req schema.CertListRequest) (*schema.CertList, error) {
	var response schema.CertList
	if err := c.DoWithContext(ctx, nil, &response, client.OptPath("cert"), client.OptQuery(certListQuery(req))); err != nil {
		return nil, err
	}
	return types.Ptr(response), nil
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func certListQuery(req schema.CertListRequest) url.Values {
	values := url.Values{}
	if req.Offset > 0 {
		values.Set("offset", strconv.FormatUint(req.Offset, 10))
	}
	if req.Limit != nil {
		values.Set("limit", strconv.FormatUint(types.Value(req.Limit), 10))
	}
	if req.IsCA != nil {
		values.Set("is_ca", strconv.FormatBool(*req.IsCA))
	}
	if req.Enabled != nil {
		values.Set("enabled", strconv.FormatBool(*req.Enabled))
	}
	for _, tag := range req.Tags {
		values.Add("tags", tag)
	}
	if req.Valid != nil {
		values.Set("valid", strconv.FormatBool(*req.Valid))
	}
	if req.Subject != nil {
		values.Set("subject", strconv.FormatUint(types.Value(req.Subject), 10))
	}
	return values
}

func certGetQuery(chain, private bool) url.Values {
	values := url.Values{}
	if chain {
		values.Set("chain", strconv.FormatBool(chain))
	}
	if private {
		values.Set("private", strconv.FormatBool(private))
	}
	return values
}

func renewRequestBody(req schema.RenewCertRequest) map[string]any {
	body := make(map[string]any)
	if req.Expiry != 0 {
		body["expiry"] = req.Expiry
	}
	if req.Subject != nil {
		body["subject"] = req.Subject
	}
	if req.Tags != nil {
		if len(req.Tags) == 0 {
			body["tags"] = []string{}
		} else {
			body["tags"] = append([]string(nil), req.Tags...)
		}
	}
	return body
}
