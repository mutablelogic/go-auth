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

package ldap

import (
	"context"
	"log/slog"
	"math/rand"
	"time"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/ldap"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

func (manager *Manager) Run(ctx context.Context, logger *slog.Logger) error {
	var retries uint

	// Connect after a short random delay
	ticker := time.NewTimer(time.Millisecond * time.Duration(rand.Intn(100)))
	defer ticker.Stop()

	// Continue to reconnect until cancelled
	for {
		select {
		case <-ctx.Done():
			if err := manager.Disconnect(); err != nil {
				logger.Error("LDAP disconnection error", "error", err.Error())
				return err
			}
			return nil
		case <-ticker.C:
			if err := manager.Connect(); err != nil {
				// Connection error
				logger.Error("LDAP connection error", "error", err.Error())
				retries = min(retries+1, schema.MaxRetries)
				ticker.Reset(schema.MinRetryInterval * time.Duration(retries*retries))
				continue
			} else {
				// Connection successful
				manager.discoveryOnce.Do(func() {
					manager.discoverSchemas(ctx, logger)
				})
				if retries > 0 {
					logger.Info("LDAP connected", "url", manager.Host())
				}
				retries = 0
				ticker.Reset(schema.MinRetryInterval * time.Duration(schema.MaxRetries))
			}
		}
	}
}
