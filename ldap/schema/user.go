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
	"net/url"

	// Packages
	types "github.com/mutablelogic/go-server/pkg/types"
)

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

// DefaultUserObjectClasses is used when no user object classes are configured.
var DefaultUserObjectClasses = []string{"inetOrgPerson"}

// WellKnownUserClasses is the list of structural object classes checked during auto-discovery.
var WellKnownUserClasses = []string{"user", "inetOrgPerson", "organizationalPerson", "person", "account"}

// WellKnownUserAuxiliaryClasses is the list of auxiliary user classes checked during auto-discovery.
var WellKnownUserAuxiliaryClasses = []string{"posixAccount"}

////////////////////////////////////////////////////////////////////////////////
// REQUESTS

// UserListRequest is a list request, which has only the members of the group, when it's set
type UserListRequest struct {
	ObjectListRequest
	Group *string `json:"group,omitempty" help:"The name of a group whose members are listed"`
}

// Query returns the request as query parameters
func (req UserListRequest) Query() url.Values {
	values := req.ObjectListRequest.Query()
	if req.Group != nil {
		values.Set("group", *req.Group)
	}
	return values
}

func (req UserListRequest) String() string {
	return types.Stringify(req)
}
