package internal

import (
	"errors"

	rootauth "github.com/djthorpe/go-auth"
	schema "github.com/djthorpe/go-auth/schema"
	upstream "github.com/google/jsonschema-go/jsonschema"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	jsonschema "github.com/mutablelogic/go-server/pkg/jsonschema"
)

func HTTPError(err error) error {
	var authErr rootauth.Err
	if !errors.As(err, &authErr) {
		return err
	}
	switch authErr {
	case rootauth.ErrNotFound:
		return httpresponse.ErrNotFound.With(err)
	case rootauth.ErrBadParameter:
		return httpresponse.ErrBadRequest.With(err)
	case rootauth.ErrConflict:
		return httpresponse.ErrConflict.With(err)
	case rootauth.ErrNotImplemented:
		return httpresponse.ErrNotImplemented.With(err)
	case rootauth.ErrInternalServerError:
		return httpresponse.ErrInternalError.With(err)
	case rootauth.ErrInvalidProvider:
		return httpresponse.ErrNotAuthorized.With(err)
	default:
		return httpresponse.ErrInternalError.With(err)
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
