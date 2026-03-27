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
	"fmt"
	"net/http"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	client "github.com/mutablelogic/go-client"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// ChangeCallback is invoked for each decoded SSE change notification.
type ChangeCallback func(schema.ChangeNotification) error

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ListenChanges connects to the protected SSE changes endpoint and invokes the
// callback for each decoded change notification until the context is cancelled,
// the stream ends, or the callback returns an error.
func (c *Client) ListenChanges(ctx context.Context, fn ChangeCallback, opts ...client.RequestOpt) error {
	if fn == nil {
		return fmt.Errorf("change callback is required")
	}

	req := client.NewRequestEx(http.MethodGet, client.ContentTypeTextStream)
	streamOpts := []client.RequestOpt{
		client.OptPath("changes"),
		client.OptNoTimeout(),
		client.OptTextStreamCallback(func(event client.TextStreamEvent) error {
			if event.Data == "" {
				return nil
			}

			var notification schema.ChangeNotification
			if err := event.Json(&notification); err != nil {
				return err
			}

			return fn(notification)
		}),
	}

	// go-client exits early when out is nil, so provide a dummy output value
	// to ensure the text stream callback path is reached.
	var response struct{}
	return c.DoWithContext(ctx, req, &response, append(streamOpts, opts...)...)
}
