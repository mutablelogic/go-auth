package auth

import (
	shared "github.com/djthorpe/go-auth/pkg/httphandler/internal"
	schema "github.com/djthorpe/go-auth/schema"
	upstream "github.com/google/jsonschema-go/jsonschema"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

func httpErr(err error) error {
	return shared.HTTPError(err)
}

func uuidSchema() *jsonschema.Schema {
	return shared.UUIDSchema()
}

func userSchema() *jsonschema.Schema {
	return shared.UserSchema()
}

func userMetaSchema() *jsonschema.Schema {
	return shared.UserMetaSchema()
}

func userGroupListSchema() *jsonschema.Schema {
	return shared.UserGroupListSchema()
}

func groupSchema() *jsonschema.Schema {
	return shared.GroupSchema()
}

func groupListSchema() *jsonschema.Schema {
	return shared.GroupListSchema()
}

func scopeListSchema() *jsonschema.Schema {
	return shared.ScopeListSchema()
}

func userListSchema() *jsonschema.Schema {
	return shared.UserListSchema()
}

func userInfoSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.UserInfo]()
	setSchemaProperty(s, "sub", uuidSchema())
	return s
}

func sessionSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.Session]()
	setSchemaProperty(s, "id", uuidSchema())
	setSchemaProperty(s, "user", uuidSchema())
	return s
}

func tokenResponseSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.TokenResponse]()
	setSchemaProperty(s, "userinfo", userInfoSchema())
	return s
}

func schemaProperty(s *jsonschema.Schema, name string) *upstream.Schema {
	return shared.SchemaProperty(s, name)
}

func setSchemaProperty(s *jsonschema.Schema, name string, prop *jsonschema.Schema) {
	shared.SetSchemaProperty(s, name, prop)
}

func unwrapSchema(s *jsonschema.Schema) *upstream.Schema {
	return shared.UnwrapSchema(s)
}
