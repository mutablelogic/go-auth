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

// Package schema has the LDAP manager's types: objects, with their LDIF,
// distinguished names, and the directory's object classes and attribute
// types, with the requests which list them, and its defaults
package schema

import (
	"time"
)

// OffsetLimit pages a list
type OffsetLimit struct {
	Offset uint64  `json:"offset,omitempty" help:"Offset within the result set" jsonschema:"Offset for pagination" example:"0"`
	Limit  *uint64 `json:"limit,omitempty" help:"Number of items to return" jsonschema:"Limit for pagination" example:"100"`
}

const (
	SchemaName   = "ldap"
	MethodPlain  = "ldap"
	MethodSecure = "ldaps"
	PortPlain    = 389
	PortSecure   = 636

	// Time to wait for the directory to connect, or answer a request
	RequestTimeout = time.Second * 30

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

	// Initial GID/UID allocated when the lastgid/lastuid device entry is first created
	InitialGID = 1000
	InitialUID = 1000
)
