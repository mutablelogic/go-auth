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

package config

import (
	"context"

	// Packages
	server "github.com/mutablelogic/go-server"
	ldap "github.com/mutablelogic/go-server/pkg/ldap"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

type task struct {
	manager *ldap.Manager
}

var _ server.Task = (*task)(nil)

////////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func NewTask(manager *ldap.Manager) (server.Task, error) {
	self := new(task)
	self.manager = manager
	return self, nil
}

////////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (task *task) Run(ctx context.Context) error {
	return task.manager.Run(ctx)
}
