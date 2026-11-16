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
	"log/slog"
	"math/rand/v2"
	"time"

	// Packages
	schema "github.com/mutablelogic/go-auth/ldap/schema"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

// Run connects to the directory, and checks the connection, reconnecting
// when it's lost, with a growing delay, or at once when an operation loses
// it, until the context is cancelled, when it disconnects
func (manager *Manager) Run(ctx context.Context, logger *slog.Logger) error {
	var retries uint

	// Connect after a short random delay
	ticker := time.NewTimer(time.Millisecond * time.Duration(rand.IntN(100)))
	defer ticker.Stop()

	// Continue to reconnect until cancelled
	for {
		select {
		case <-ctx.Done():
			// The context is cancelled, so the disconnection has one which
			// isn't, with the same values, such as its span
			if err := manager.Disconnect(context.WithoutCancel(ctx)); err != nil {
				logger.Error("LDAP disconnection error", "error", err.Error())
				return err
			}
			return nil
		case <-ticker.C:
			if err := manager.Connect(ctx); err != nil {
				logger.Error("LDAP connection error", "error", err.Error())
				retries = min(retries+1, schema.MaxRetries)
				ticker.Reset(schema.MinRetryInterval * time.Duration(retries*retries))
				continue
			}
			if retries > 0 {
				logger.Info("LDAP connected", "url", manager.Host())
			}
			retries = 0
			ticker.Reset(schema.MinRetryInterval * time.Duration(schema.MaxRetries))
		case <-manager.lost:
			// An operation lost the connection, so reconnect now
			ticker.Reset(0)
		}
	}
}
