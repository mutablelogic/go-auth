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
