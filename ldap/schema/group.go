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
// TYPES

type Group struct {
	DN          *DN      `json:"dn,omitempty"`
	ObjectClass []string `json:"objectclass,omitempty"`
}

////////////////////////////////////////////////////////////////////////////////
// GLOBALS

// DefaultGroupObjectClasses is used when no group object classes are configured.
var DefaultGroupObjectClasses = []string{"groupOfNames"}

// WellKnownGroupClasses is the list of object classes checked during auto-discovery.
var WellKnownGroupClasses = []string{"group", "posixGroup", "groupOfNames", "groupOfUniqueNames", "groupOfMembers"}

////////////////////////////////////////////////////////////////////////////////
// REQUESTS

// GroupListRequest is a list request, which has only the groups of the user, when it's set
type GroupListRequest struct {
	ListRequest
	User   *string `json:"user,omitempty" help:"The name of a user whose groups are listed"`
	UserDN *string `json:"user_dn,omitempty" help:"The DN of a user whose groups are listed, rather than its name"`
}

// Query returns the request as query parameters
func (req GroupListRequest) Query() url.Values {
	values := req.ListRequest.Query()
	if req.User != nil {
		values.Set("user", *req.User)
	}
	if req.UserDN != nil {
		values.Set("user_dn", *req.UserDN)
	}
	return values
}

func (req GroupListRequest) String() string {
	return types.Stringify(req)
}
