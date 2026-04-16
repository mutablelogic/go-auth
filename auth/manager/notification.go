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

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	pg "github.com/mutablelogic/go-pg"
	broadcaster "github.com/mutablelogic/go-pg/pkg/broadcaster"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// ChangeNotification invokes callback for each table change notification until
// the caller context or manager notification listener is cancelled.
func (m *Manager) ChangeNotification(ctx context.Context, callback func(schema.ChangeNotification)) error {
	if callback == nil {
		return pg.ErrBadParameter.With("callback is required")
	}
	if m.notifications == nil {
		return pg.ErrNotAvailable.With("notifications are unavailable")
	}

	return m.notifications.Subscribe(ctx, func(change broadcaster.ChangeNotification) {
		callback(schema.ChangeNotification{
			Schema: change.Schema,
			Table:  change.Table,
			Action: change.Action,
		})
	})
}
