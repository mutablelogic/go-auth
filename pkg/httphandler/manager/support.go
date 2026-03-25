package manager

import (
	// Packages
	shared "github.com/djthorpe/go-auth/pkg/httphandler/internal"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

func httpErr(err error) error {
	return shared.HTTPError(err)
}

func uuidSchema() *jsonschema.Schema { return shared.UUIDSchema() }
func userSchema() *jsonschema.Schema {
	return shared.UserSchema()
}
func userMetaSchema() *jsonschema.Schema      { return shared.UserMetaSchema() }
func userGroupListSchema() *jsonschema.Schema { return shared.UserGroupListSchema() }
func groupSchema() *jsonschema.Schema         { return shared.GroupSchema() }
func groupListSchema() *jsonschema.Schema {
	return shared.GroupListSchema()
}
func scopeListSchema() *jsonschema.Schema {
	return shared.ScopeListSchema()
}
func userListSchema() *jsonschema.Schema {
	return shared.UserListSchema()
}
