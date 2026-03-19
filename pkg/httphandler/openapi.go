package httphandler

import (
	// Packages
	schema "github.com/djthorpe/go-auth/schema"
	upstream "github.com/google/jsonschema-go/jsonschema"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func uuidSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[string]()
	s.Format = "uuid"
	return s
}

func userSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.User]()
	setSchemaProperty(s, "id", uuidSchema())
	return s
}

func userInfoSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.UserInfo]()
	setSchemaProperty(s, "sub", uuidSchema())
	return s
}

func userListSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.UserList]()
	if body := schemaProperty(s, "body"); body != nil {
		body.Items = unwrapSchema(userSchema())
	}
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
	if s == nil || s.Properties == nil {
		return nil
	}
	return s.Properties[name]
}

func setSchemaProperty(s *jsonschema.Schema, name string, prop *jsonschema.Schema) {
	if s == nil || s.Properties == nil {
		return
	}
	s.Properties[name] = unwrapSchema(prop)
}

func unwrapSchema(s *jsonschema.Schema) *upstream.Schema {
	if s == nil {
		return nil
	}
	return &s.Schema
}
