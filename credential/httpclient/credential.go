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
	"io"
	"net/http"
	"strings"

	// Packages
	credential "github.com/mutablelogic/go-auth/credential"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// textPayload is a POST request with a text/plain body, which accepts a
// JSON response
type textPayload struct {
	io.Reader
}

func (textPayload) Method() string { return http.MethodPost }
func (textPayload) Accept() string { return types.ContentTypeJSON }
func (textPayload) Type() string   { return types.ContentTypeTextPlain }

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - PROVIDER

// SetCredential stores the credential, whose value is JSON, replacing any
// credential with the key, and its description, when it's set, which is
// kept when it isn't, and removed when it's empty
func (c *Client) SetCredential(ctx context.Context, set credential.CredentialSet) (*credential.Credential, error) {
	req, err := client.NewJSONRequestEx(http.MethodPut, set, types.ContentTypeAny)
	if err != nil {
		return nil, err
	}
	var response credential.Credential
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("credential")); err != nil {
		return nil, clientErr(err)
	}
	return &response, nil
}

// GetCredential gets the credential for the key, with the passphrase it was
// encrypted with, and decodes it into result, which can be any type the
// credential's JSON decodes into, such as a json.RawMessage. Only the
// backends which encrypt with their own passphrases return credentials.
func (c *Client) GetCredential(ctx context.Context, key, passphrase string, result any) error {
	return clientErr(c.DoWithContext(ctx, textPayload{Reader: strings.NewReader(passphrase)}, result, client.OptPath("credential", key)))
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - MANAGER

// ListCredentials returns the stored credentials, in key order, without
// their values
func (c *Client) ListCredentials(ctx context.Context) (*credential.CredentialList, error) {
	var response credential.CredentialList
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath("credential")); err != nil {
		return nil, clientErr(err)
	}
	return &response, nil
}

// GetCredentialMeta returns the key of the stored credential, and the time
// it was last changed, without its value
func (c *Client) GetCredentialMeta(ctx context.Context, key string) (*credential.Credential, error) {
	var response credential.Credential
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath("credential", key)); err != nil {
		return nil, clientErr(err)
	}
	return &response, nil
}

// DescribeCredential changes the description of the stored credential for
// the key, without its value, or removes it, when it's empty
func (c *Client) DescribeCredential(ctx context.Context, key, description string) (*credential.Credential, error) {
	req, err := client.NewJSONRequestEx(http.MethodPatch, credential.CredentialDescription{Description: description}, types.ContentTypeAny)
	if err != nil {
		return nil, err
	}
	var response credential.Credential
	if err := c.DoWithContext(ctx, req, &response, client.OptPath("credential", key)); err != nil {
		return nil, clientErr(err)
	}
	return &response, nil
}

// DeleteCredential deletes the stored credential for the key
func (c *Client) DeleteCredential(ctx context.Context, key string) error {
	return clientErr(c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("credential", key)))
}

// RotateCredential re-encrypts the credential for the key with the latest
// passphrase version. Returns auth.ErrNotModified when it already uses it.
func (c *Client) RotateCredential(ctx context.Context, key string) error {
	return clientErr(c.DoWithContext(ctx, client.MethodPost, nil, client.OptPath("credential", key, "rotate")))
}
