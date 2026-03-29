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

package internal

import (
	"errors"
	"strings"

	// Packages
	rootauth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema/auth"
	upstream "github.com/google/jsonschema-go/jsonschema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

func HTTPError(err error) error {
	var authErr rootauth.Err
	if !errors.As(err, &authErr) {
		return err
	}
	reason := err.Error()
	prefix := authErr.Error() + ": "
	reason = strings.TrimPrefix(reason, prefix)
	switch authErr {
	case rootauth.ErrNotFound:
		return httpresponse.ErrNotFound.With(reason)
	case rootauth.ErrBadParameter:
		return httpresponse.ErrBadRequest.With(reason)
	case rootauth.ErrConflict:
		return httpresponse.ErrConflict.With(reason)
	case rootauth.ErrNotImplemented:
		return httpresponse.ErrNotImplemented.With(reason)
	case rootauth.ErrServiceUnavailable:
		return httpresponse.ErrServiceUnavailable.With(reason)
	case rootauth.ErrInternalServerError:
		return httpresponse.ErrInternalError.With(reason)
	case rootauth.ErrInvalidProvider:
		return httpresponse.ErrNotAuthorized.With(reason)
	case rootauth.ErrForbidden:
		return httpresponse.ErrForbidden.With(reason)
	default:
		return httpresponse.ErrInternalError.With(reason)
	}
}

func UUIDSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[string]()
	s.Format = "uuid"
	return s
}

func UserSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.User]()
	SetSchemaProperty(s, "id", UUIDSchema())
	return s
}

func UserMetaSchema() *jsonschema.Schema {
	return jsonschema.MustFor[schema.UserMeta]()
}

func UserGroupListSchema() *jsonschema.Schema {
	return jsonschema.MustFor[schema.UserGroupList]()
}

func GroupSchema() *jsonschema.Schema {
	return jsonschema.MustFor[schema.Group]()
}

func GroupListSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.GroupList]()
	if body := SchemaProperty(s, "body"); body != nil {
		body.Items = UnwrapSchema(GroupSchema())
	}
	return s
}

func ScopeListSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.ScopeList]()
	if body := SchemaProperty(s, "body"); body != nil {
		body.Items = UnwrapSchema(jsonschema.MustFor[string]())
	}
	return s
}

func UserListSchema() *jsonschema.Schema {
	s := jsonschema.MustFor[schema.UserList]()
	if body := SchemaProperty(s, "body"); body != nil {
		body.Items = UnwrapSchema(UserSchema())
	}
	return s
}

func SchemaProperty(s *jsonschema.Schema, name string) *upstream.Schema {
	if s == nil || s.Properties == nil {
		return nil
	}
	return s.Properties[name]
}

func SetSchemaProperty(s *jsonschema.Schema, name string, prop *jsonschema.Schema) {
	if s == nil || s.Properties == nil {
		return
	}
	s.Properties[name] = UnwrapSchema(prop)
}

func UnwrapSchema(s *jsonschema.Schema) *upstream.Schema {
	if s == nil {
		return nil
	}
	return &s.Schema
}
