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
	"time"
)

const (
	SchemaName   = "ldap"
	APIPrefix    = "/ldap/v1"
	MethodPlain  = "ldap"
	MethodSecure = "ldaps"
	PortPlain    = 389
	PortSecure   = 636

	// Time between connection retries
	MinRetryInterval = time.Second * 5
	MaxRetries       = 10

	// Maximum number of entries to return in a single request
	MaxListPaging = 500

	// Maximum list entries to return
	MaxListEntries = 1000

	// Attributes
	AttrObjectClasses  = "objectClasses"
	AttrAttributeTypes = "attributeTypes"
	AttrSubSchemaDN    = "subschemaSubentry"
)

////////////////////////////////////////////////////////////////////////////////
// TYPES

type Group struct {
	DN          *DN      `json:"dn,omitempty"`
	ObjectClass []string `json:"objectclass,omitempty"`
}
