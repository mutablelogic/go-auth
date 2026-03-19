package manager

import (
	"context"
	"time"
)

// Run periodically prunes stale sessions until the context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, err := m.CleanupSessions(ctx); err != nil {
		return err
	}

	ticker := time.NewTicker(m.cleanupint)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if _, err := m.CleanupSessions(ctx); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return err
			}
		}
	}
}
