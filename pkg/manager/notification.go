package manager

import (
	"context"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
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
