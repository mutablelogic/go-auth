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
	"errors"
	"net/http"

	// Packages
	coremanager "github.com/djthorpe/go-auth/pkg/manager"
	schema "github.com/djthorpe/go-auth/schema/auth"
	pg "github.com/mutablelogic/go-pg"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
	openapi "github.com/mutablelogic/go-server/pkg/openapi/schema"
	types "github.com/mutablelogic/go-server/pkg/types"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ChangesHandler streams change notifications as server-sent events.
func ChangesHandler(mgr *coremanager.Manager) (string, http.HandlerFunc, *openapi.PathItem) {
	return "changes", func(w http.ResponseWriter, r *http.Request) {
			switch r.Method {
			case http.MethodGet:
				_ = streamChanges(r.Context(), mgr, w, r)
			default:
				_ = httpresponse.Error(w, httpresponse.Err(http.StatusMethodNotAllowed), r.Method)
			}
		}, &openapi.PathItem{
			Summary:     "Change notifications",
			Description: "Streams table change notifications as server-sent events.",
			Get: &openapi.Operation{
				Tags:        []string{"Changes"},
				Summary:     "Stream changes",
				Description: "Requires an Accept header of text/event-stream and streams change notifications until the client disconnects.",
				Responses: map[string]openapi.Response{
					"200": {
						Description: "Text/event-stream of change notifications.",
						Content: map[string]openapi.MediaType{
							types.ContentTypeTextStream: {
								Schema: jsonschema.MustFor[schema.ChangeNotification](),
							},
						},
					},
					"406": {
						Description: "The request must accept text/event-stream.",
					},
					"503": {
						Description: "Change notifications are not configured on the manager.",
					},
				},
			},
		}
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func streamChanges(ctx context.Context, mgr *coremanager.Manager, w http.ResponseWriter, r *http.Request) error {
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
