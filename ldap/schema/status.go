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

package schema

import (
	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

// Status is the LDAP manager's directory, and whether it's connected, which
// a server's configuration has, for its frontend
type Status struct {
	Host      string `json:"host" help:"Host of the directory"`
	Port      uint   `json:"port" help:"Port of the directory"`
	User      string `json:"user" help:"DN the manager binds as"`
	Connected bool   `json:"connected" help:"Whether the manager is connected to the directory"`
	BaseDN    string `json:"base_dn" help:"Base DN, which every DN is under"`
	UserDN    string `json:"user_dn,omitempty" help:"DN of the users, when the manager has users"`
	GroupDN   string `json:"group_dn,omitempty" help:"DN of the groups, when the manager has groups"`
}

////////////////////////////////////////////////////////////////////////////////
// STRINGIFY

func (s Status) String() string {
	return types.Stringify(s)
}
