package manager

import (
	"context"
	"time"
)

// Run periodically prunes stale sessions until the context is cancelled.
func (m *Manager) Run(ctx context.Context) error {
	interval := m.cleanupint
	if interval <= 0 {
		interval = DefaultCleanupInterval
	}
	ticker := time.NewTicker(interval)
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
