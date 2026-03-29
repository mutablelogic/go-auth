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

package provider

import (
	"net/url"

	// Packages
	schema "github.com/djthorpe/go-auth/schema/auth"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

const (
	UserPath = "user"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// UserResourceProvider is a concrete provider for schema.User resources.
type UserResourceProvider = Provider[schema.UserID, schema.UserMeta, schema.User]

// UserListProvider is a concrete list provider for schema.User resources.
type UserListProvider = ListProvider[schema.UserListRequest, schema.UserList]

type UserProvider struct {
	UserResourceProvider
	UserListProvider
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewUserProvider creates a provider for schema.User resources and collections.
func NewUserProvider(base *url.URL) *UserProvider {
	return &UserProvider{
		UserResourceProvider: NewProvider[schema.UserID, schema.UserMeta, schema.User](base, UserPath, func(user schema.User) schema.UserID {
			return user.ID
		}),
		UserListProvider: NewListProvider[schema.UserListRequest, schema.UserList](base, UserPath),
	}
}
