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

package httphandler

import (
	"context"
	"errors"
	"net/http"

	// Packages
	managerpkg "github.com/mutablelogic/go-auth/auth/manager"
	schema "github.com/mutablelogic/go-auth/auth/schema"
	pg "github.com/mutablelogic/go-pg"
	httprequest "github.com/mutablelogic/go-server/pkg/httprequest"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	opts "github.com/mutablelogic/go-server/pkg/openapi"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ChangesHandler returns a path and pathitem for the changes SSE endpoint.
func ChangesHandler(mgr *managerpkg.Manager, doc *opts.MarkdownDoc) (string, *jsonschema.Schema, httprequest.PathItem) {
	return "changes", nil, httprequest.NewPathItem(
		"Change notifications",
		"Streams table change notifications as server-sent events.",
		"Changes",
	).Get(
		func(w http.ResponseWriter, r *http.Request) {
			_ = streamChanges(r.Context(), mgr, w, r)
		},
		"Stream changes",
		opts.WithDescription(doc.Section(3, "GET /{prefix}/changes").Body),
		opts.WithResponse(200, types.ContentTypeTextStream, jsonschema.MustFor[schema.ChangeNotification]()),
		opts.WithErrorResponse(406, "The request must accept text/event-stream."),
		opts.WithErrorResponse(503, "Change notifications are not configured on the manager."),
	)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func streamChanges(ctx context.Context, mgr *managerpkg.Manager, w http.ResponseWriter, r *http.Request) error {
	if mimetype, err := types.AcceptContentType(r); err != nil || mimetype != types.ContentTypeTextStream {
		return httpresponse.Error(w, httpresponse.Err(http.StatusNotAcceptable), types.ContentTypeTextStream)
	}

	changes := make(chan schema.ChangeNotification)
	if err := mgr.ChangeNotification(ctx, func(change schema.ChangeNotification) {
		select {
		case changes <- change:
		case <-ctx.Done():
		}
	}); err != nil {
		switch {
		case errors.Is(err, pg.ErrNotAvailable):
			return httpresponse.Error(w, httpresponse.Err(http.StatusServiceUnavailable), err.Error())
		case errors.Is(err, pg.ErrBadParameter):
			return httpresponse.Error(w, httpresponse.Err(http.StatusBadRequest), err.Error())
		default:
			return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError), err.Error())
		}
	}

	stream := httpresponse.NewTextStream(w)
	if stream == nil {
		return httpresponse.Error(w, httpresponse.Err(http.StatusInternalServerError), "failed to create text stream")
	}
	defer stream.Close()

	for {
		select {
		case change := <-changes:
			stream.Write("change", change)
		case <-ctx.Done():
			return nil
		}
	}
}
