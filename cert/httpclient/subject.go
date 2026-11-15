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
	"strconv"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	cert "github.com/mutablelogic/go-auth/cert/cert"
	client "github.com/mutablelogic/go-client"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - SUBJECTS

// ListSubjects returns a page of the subjects, with the number of
// certificates which use each
func (c *Client) ListSubjects(ctx context.Context, req cert.SubjectListRequest) (*cert.SubjectList, error) {
	var response cert.SubjectList
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath("subject"), client.OptQuery(req.Query())); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// GetSubject returns a subject, with the number of certificates which use it
func (c *Client) GetSubject(ctx context.Context, id uint64) (*cert.Subject, error) {
	var response cert.Subject
	if err := c.DoWithContext(ctx, client.MethodGet, &response, client.OptPath("subject", strconv.FormatUint(id, 10))); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}

// CreateSubject creates a subject, or returns an identical one, when it's
// stored
func (c *Client) CreateSubject(ctx context.Context, meta cert.SubjectMeta) (*cert.Subject, error) {
	return c.sendSubject(ctx, http.MethodPost, meta, "subject")
}

// UpdateSubject updates a subject which no certificate uses. A field which
// isn't set is kept, and an empty one removed.
func (c *Client) UpdateSubject(ctx context.Context, id uint64, meta cert.SubjectMeta) (*cert.Subject, error) {
	return c.sendSubject(ctx, http.MethodPatch, meta, "subject", strconv.FormatUint(id, 10))
}

// DeleteSubject deletes a subject which no certificate uses
func (c *Client) DeleteSubject(ctx context.Context, id uint64) error {
	return auth.ClientError(c.DoWithContext(ctx, client.MethodDelete, nil, client.OptPath("subject", strconv.FormatUint(id, 10))))
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

// sendSubject sends the subject as JSON, and returns the subject in the
// response
func (c *Client) sendSubject(ctx context.Context, method string, meta cert.SubjectMeta, path ...any) (*cert.Subject, error) {
	req, err := client.NewJSONRequestEx(method, meta, types.ContentTypeAny)
	if err != nil {
		return nil, err
	}
	var response cert.Subject
	if err := c.DoWithContext(ctx, req, &response, client.OptPath(path...)); err != nil {
		return nil, auth.ClientError(err)
	}
	return &response, nil
}
