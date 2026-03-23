package provider

import (
	"net/url"

	// Packages
	schema "github.com/djthorpe/go-auth/schema"
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
