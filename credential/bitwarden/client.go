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

package bitwarden

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// client calls the Bitwarden identity and API servers, for a machine
// account's access token
type client struct {
	http        *http.Client
	apiURL      string
	identityURL string
	token       *accessToken

	// The session, after logging in
	sync.Mutex
	bearer    string
	refreshAt time.Time
	orgID     string
	orgKey    *key
}

// secret is a decrypted secret
type secret struct {
	ID         string
	Key        string
	Value      string
	Note       string
	ProjectIDs []string
	Revised    time.Time
}

// encryptedSecret is a secret as the API returns it, with its key, value and
// note encrypted with the organization's key
type encryptedSecret struct {
	ID       string `json:"id"`
	Key      string `json:"key"`
	Value    string `json:"value,omitempty"`
	Note     string `json:"note,omitempty"`
	Revised  string `json:"revisionDate,omitempty"`
	Projects []struct {
		ID string `json:"id"`
	} `json:"projects,omitempty"`
}

// secretRequest creates or updates a secret, with its key, value and note
// encrypted with the organization's key
type secretRequest struct {
	Key          string   `json:"key"`
	Value        string   `json:"value"`
	Note         string   `json:"note"`
	ProjectIDs   []string `json:"projectIds,omitempty"`
	ValueChanged *bool    `json:"valueChanged,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	// refreshBefore is how long before the bearer token expires that it's
	// replaced, or halfway through its life, when that's sooner
	refreshBefore = time.Minute
)

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - SECRETS

// listSecrets returns the identifiers and decrypted keys of the secrets the
// machine account can read
func (c *client) listSecrets(ctx context.Context) ([]secret, error) {
	var response struct {
		Secrets []encryptedSecret `json:"secrets"`
	}
	orgID, orgKey, err := c.session(ctx)
	if err != nil {
		return nil, err
	} else if err := c.do(ctx, http.MethodGet, "/organizations/"+url.PathEscape(orgID)+"/secrets", nil, &response); err != nil {
		return nil, err
	}
	result := make([]secret, 0, len(response.Secrets))
	for _, s := range response.Secrets {
		key, err := orgKey.decrypt(s.Key)
		if err != nil {
			return nil, auth.ErrInternalServerError.Withf("secret %q key: %w", s.ID, err)
		}
		revised, _ := time.Parse(time.RFC3339Nano, s.Revised)
		result = append(result, secret{ID: s.ID, Key: string(key), Revised: revised.UTC()})
	}
	return result, nil
}

// getSecret returns the decrypted secret
func (c *client) getSecret(ctx context.Context, id string) (*secret, error) {
	var response encryptedSecret
	_, orgKey, err := c.session(ctx)
	if err != nil {
		return nil, err
	} else if err := c.do(ctx, http.MethodGet, "/secrets/"+url.PathEscape(id), nil, &response); err != nil {
		return nil, err
	}
	return decryptSecret(orgKey, &response)
}

// createSecret creates a secret in the projects
func (c *client) createSecret(ctx context.Context, s secret) error {
	orgID, orgKey, err := c.session(ctx)
	if err != nil {
		return err
	}
	request, err := encryptSecret(orgKey, s)
	if err != nil {
		return err
	}
	return c.do(ctx, http.MethodPost, "/organizations/"+url.PathEscape(orgID)+"/secrets", request, nil)
}

// updateSecret replaces the secret's key, value, note and projects
func (c *client) updateSecret(ctx context.Context, s secret) error {
	_, orgKey, err := c.session(ctx)
	if err != nil {
		return err
	}
	request, err := encryptSecret(orgKey, s)
	if err != nil {
		return err
	}
	changed := true
	request.ValueChanged = &changed
	return c.do(ctx, http.MethodPut, "/secrets/"+url.PathEscape(s.ID), request, nil)
}

// deleteSecret deletes the secret
func (c *client) deleteSecret(ctx context.Context, id string) error {
	var response struct {
		Data []struct {
			ID    string `json:"id"`
			Error string `json:"error"`
		} `json:"data"`
	}
	if _, _, err := c.session(ctx); err != nil {
		return err
	} else if err := c.do(ctx, http.MethodPost, "/secrets/delete", []string{id}, &response); err != nil {
		return err
	}

	// Each secret has an error, when it isn't deleted
	for _, result := range response.Data {
		if result.ID == id && result.Error != "" {
			if strings.Contains(strings.ToLower(result.Error), "not found") {
				return auth.ErrNotFound.Withf("secret %q: %s", id, result.Error)
			}
			return auth.ErrForbidden.Withf("secret %q: %s", id, result.Error)
		}
	}
	return nil
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - SESSION

// session returns the organization and its key, logging in when there's no
// bearer token, or it's about to expire
func (c *client) session(ctx context.Context) (string, *key, error) {
	c.Lock()
	defer c.Unlock()
	if c.bearer == "" || !time.Now().Before(c.refreshAt) {
		if err := c.login(ctx); err != nil {
			return "", nil, err
		}
	}
	return c.orgID, c.orgKey, nil
}

// login exchanges the access token for a bearer token, and decrypts the
// organization's key from the response
func (c *client) login(ctx context.Context) error {
	form := url.Values{
		"scope":         {"api.secrets"},
		"client_id":     {c.token.id},
		"client_secret": {c.token.secret},
		"grant_type":    {"client_credentials"},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.identityURL+"/connect/token", strings.NewReader(form.Encode()))
	if err != nil {
		return auth.ErrBadParameter.Withf("identity url: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=utf-8")
	req.Header.Set("Accept", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return auth.ErrServiceUnavailable.Withf("bitwarden login: %w", err)
	}
	defer resp.Body.Close()

	// The identity server returns 400 for an invalid client
	if resp.StatusCode == http.StatusBadRequest {
		return auth.ErrForbidden.Withf("bitwarden login: %s", readError(resp))
	} else if err := statusErr("bitwarden login", resp); err != nil {
		return err
	}
	var response struct {
		AccessToken      string `json:"access_token"`
		ExpiresIn        int64  `json:"expires_in"`
		EncryptedPayload string `json:"encrypted_payload"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&response); err != nil {
		return auth.ErrServiceUnavailable.Withf("bitwarden login: %w", err)
	} else if response.AccessToken == "" || response.EncryptedPayload == "" {
		return auth.ErrServiceUnavailable.With("bitwarden login: response has no token or payload")
	}

	// The payload, decrypted with the access token's key, is the
	// organization's key
	var payload struct {
		EncryptionKey string `json:"encryptionKey"`
	}
	if data, err := c.token.key.decrypt(response.EncryptedPayload); err != nil {
		return auth.ErrForbidden.Withf("bitwarden login: payload: %w", err)
	} else if err := json.Unmarshal(data, &payload); err != nil {
		return auth.ErrServiceUnavailable.Withf("bitwarden login: payload: %w", err)
	}
	keyData, err := base64.StdEncoding.DecodeString(payload.EncryptionKey)
	if err != nil {
		return auth.ErrServiceUnavailable.Withf("bitwarden login: organization key: %w", err)
	}
	orgKey, err := newKey(keyData)
	if err != nil {
		return auth.ErrServiceUnavailable.Withf("bitwarden login: organization key: %w", err)
	}

	// The organization is a claim in the bearer token
	orgID, err := jwtOrganization(response.AccessToken)
	if err != nil {
		return auth.ErrServiceUnavailable.Withf("bitwarden login: %w", err)
	}

	// Set the session
	c.bearer = response.AccessToken
	expiresIn := time.Duration(response.ExpiresIn) * time.Second
	c.refreshAt = time.Now().Add(expiresIn - min(refreshBefore, expiresIn/2))
	c.orgID = orgID
	c.orgKey = orgKey
	return nil
}

// do calls the API, with a JSON body when it's set, and decodes the JSON
// response into out, when it's set. When the bearer token is rejected, it
// logs in again, and retries once.
func (c *client) do(ctx context.Context, method, path string, body, out any) error {
	for attempt := 0; ; attempt++ {
		c.Lock()
		bearer := c.bearer
		c.Unlock()

		var reader io.Reader
		if body != nil {
			data, err := json.Marshal(body)
			if err != nil {
				return auth.ErrInternalServerError.Withf("%s %s: %w", method, path, err)
			}
			reader = bytes.NewReader(data)
		}
		req, err := http.NewRequestWithContext(ctx, method, c.apiURL+path, reader)
		if err != nil {
			return auth.ErrBadParameter.Withf("api url: %w", err)
		}
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.Header.Set("Accept", "application/json")
		if body != nil {
			req.Header.Set("Content-Type", "application/json")
		}
		resp, err := c.http.Do(req)
		if err != nil {
			return auth.ErrServiceUnavailable.Withf("%s %s: %w", method, path, err)
		}

		// Log in again when the bearer token is rejected, such as when it's
		// revoked before it expires
		if resp.StatusCode == http.StatusUnauthorized && attempt == 0 {
			resp.Body.Close()
			c.Lock()
			err := c.login(ctx)
			c.Unlock()
			if err != nil {
				return err
			}
			continue
		}

		defer resp.Body.Close()
		if err := statusErr(method+" "+path, resp); err != nil {
			return err
		} else if out != nil {
			if err := json.NewDecoder(resp.Body).Decode(out); err != nil {
				return auth.ErrServiceUnavailable.Withf("%s %s: %w", method, path, err)
			}
		}
		return nil
	}
}

////////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS - HELPERS

// decryptSecret decrypts the secret's key, value and note
func decryptSecret(orgKey *key, s *encryptedSecret) (*secret, error) {
	result := &secret{ID: s.ID}
	for _, field := range []struct {
		value string
		dest  *string
	}{{s.Key, &result.Key}, {s.Value, &result.Value}, {s.Note, &result.Note}} {
		if field.value == "" {
			continue
		}
		data, err := orgKey.decrypt(field.value)
		if err != nil {
			return nil, auth.ErrInternalServerError.Withf("secret %q: %w", s.ID, err)
		}
		*field.dest = string(data)
	}
	for _, project := range s.Projects {
		result.ProjectIDs = append(result.ProjectIDs, project.ID)
	}
	return result, nil
}

// encryptSecret encrypts the secret's key, value and note for a request
func encryptSecret(orgKey *key, s secret) (*secretRequest, error) {
	request := &secretRequest{ProjectIDs: s.ProjectIDs}
	for _, field := range []struct {
		value string
		dest  *string
	}{{strings.TrimSpace(s.Key), &request.Key}, {s.Value, &request.Value}, {strings.TrimSpace(s.Note), &request.Note}} {
		data, err := orgKey.encrypt([]byte(field.value))
		if err != nil {
			return nil, auth.ErrInternalServerError.Withf("secret %q: %w", s.Key, err)
		}
		*field.dest = data
	}
	return request, nil
}

// jwtOrganization returns the "organization" claim of a JWT, which isn't
// verified, as it's only read to address the API, which verifies it
func jwtOrganization(token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return "", fmt.Errorf("bearer token isn't a JWT")
	}
	data, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return "", fmt.Errorf("bearer token: %w", err)
	}
	var claims struct {
		Organization string `json:"organization"`
	}
	if err := json.Unmarshal(data, &claims); err != nil {
		return "", fmt.Errorf("bearer token: %w", err)
	} else if !isUUID(claims.Organization) {
		return "", fmt.Errorf("bearer token has no organization")
	}
	return claims.Organization, nil
}

// statusErr returns an auth error for a response which isn't successful
func statusErr(op string, resp *http.Response) error {
	switch {
	case resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case resp.StatusCode == http.StatusBadRequest:
		return auth.ErrBadParameter.Withf("%s: %s", op, readError(resp))
	case resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		return auth.ErrForbidden.Withf("%s: %s", op, readError(resp))
	case resp.StatusCode == http.StatusNotFound:
		return auth.ErrNotFound.Withf("%s: %s", op, readError(resp))
	default:
		return auth.ErrServiceUnavailable.Withf("%s: %s", op, readError(resp))
	}
}

// readError returns the status and the start of the response body, which
// doesn't contain secrets, as it's an error
func readError(resp *http.Response) string {
	data, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if message := strings.TrimSpace(string(data)); message != "" {
		return resp.Status + ": " + message
	}
	return resp.Status
}
