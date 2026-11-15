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
	"strings"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	cert "github.com/mutablelogic/go-auth/cert/cert"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - CERTIFICATE AUTHORITIES

// CreateCA creates a certificate authority, signed by the root
func (c *Client) CreateCA(ctx context.Context, req cert.CreateCertRequest) (*cert.Certificate, error) {
	return c.send(ctx, http.MethodPost, req, "ca")
}

// RenewCA renews a version of a certificate authority, or its latest
// version when the key has no serial
func (c *Client) RenewCA(ctx context.Context, key cert.CertKey, req cert.RenewCertRequest) (*cert.Certificate, error) {
	return c.send(ctx, http.MethodPost, req, keyPath("ca", key, "renew")...)
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - CERTIFICATES

// ListCerts returns the certificates, other than the root, without their
// private keys
func (c *Client) ListCerts(ctx context.Context, req cert.CertListRequest) (*cert.CertList, error) {
	var response cert.CertList
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath("cert"), client.OptQuery(req.Query())); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// GetCert returns a version of a certificate, or its latest version when the
// key has no serial, with its issuer chain when it's asked for. A disabled
// certificate is a conflict.
func (c *Client) GetCert(ctx context.Context, key cert.CertKey, req cert.GetCertRequest) (*cert.CertBundle, error) {
	var response cert.CertBundle
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath(keyPath("cert", key)...), client.OptQuery(req.Query())); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// GetPrivateKey returns a version of a leaf certificate, or its latest
// version when the key has no serial, with its private key, decrypted, and
// its issuer chain when it's asked for. A certificate authority's private
// key is never returned.
func (c *Client) GetPrivateKey(ctx context.Context, key cert.CertKey, req cert.GetCertRequest) (*cert.CertBundle, error) {
	var response cert.CertBundle
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath(keyPath("cert", key, "key")...), client.OptQuery(req.Query())); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// CreateCert creates a leaf certificate, signed by a version of a
// certificate authority, or its latest version when the key has no serial
func (c *Client) CreateCert(ctx context.Context, req cert.CreateCertRequest, ca cert.CertKey) (*cert.Certificate, error) {
	return c.send(ctx, http.MethodPost, req, keyPath("cert", ca)...)
}

// UpdateCert updates the enabled state and tags of a version of a
// certificate, or its latest version when the key has no serial. Empty tags
// remove them, and nil tags are kept.
func (c *Client) UpdateCert(ctx context.Context, key cert.CertKey, meta cert.CertMeta) (*cert.Certificate, error) {
	// Tags are omitted when they're empty, so they're sent as an empty list
	// to remove them
	body := map[string]any{}
	if meta.Enabled != nil {
		body["enabled"] = *meta.Enabled
	}
	if meta.Tags != nil {
		body["tags"] = append([]string{}, meta.Tags...)
	}
	return c.send(ctx, http.MethodPatch, body, keyPath("cert", key)...)
}

// RenewCert renews a version of a leaf certificate, or its latest version
// when the key has no serial
func (c *Client) RenewCert(ctx context.Context, key cert.CertKey, req cert.RenewCertRequest) (*cert.Certificate, error) {
	return c.send(ctx, http.MethodPost, req, keyPath("cert", key, "renew")...)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// send sends the body as JSON, and returns the certificate in the response
func (c *Client) send(ctx context.Context, method string, body any, path ...any) (*cert.Certificate, error) {
	req, err := client.NewJSONRequestEx(method, body, types.ContentTypeAny)
	if err != nil {
		return nil, err
	}
	var response cert.Certificate
	if err := c.DoWithContext(ctx, req, &response, client.OptPath(path...)); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// keyPath is the path of a certificate's version, or of its latest version
// when the key has no serial, followed by the rest of the path
func keyPath(prefix string, key cert.CertKey, rest ...any) []any {
	path := []any{prefix, key.Name}
	if serial := strings.TrimSpace(key.Serial); serial != "" {
		path = append(path, serial)
	}
	return append(path, rest...)
}
