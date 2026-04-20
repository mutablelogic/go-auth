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

package manager

import (
	"context"
	"strings"

	// Packages
	schema "github.com/mutablelogic/go-auth/auth/schema"
	otel "github.com/mutablelogic/go-client/pkg/otel"
	pg "github.com/mutablelogic/go-pg"
	types "github.com/mutablelogic/go-server/pkg/types"
	attribute "go.opentelemetry.io/otel/attribute"
)

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (m *Manager) CreateKey(ctx context.Context, user schema.UserID, meta schema.KeyMeta) (_ *schema.Key, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "CreateKey",
		attribute.String("user", user.String()),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	var result schema.Key
	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		if err := conn.With("user", user).Insert(ctx, &result, meta); err != nil {
			return err
		}

		// Revise the token to include a prefix if needed
		if hook, ok := m.opt.hooks.(APIKeyHook); ok && hook != nil {
			if prefix, err := hook.OnKeyCreate(ctx, result); err != nil {
				return err
			} else if prefix != "" {
				result.Token = prefix + result.Token
			}
		}

		// Return success
		return nil
	}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(result), nil
}

func (m *Manager) GetKeyByToken(ctx context.Context, token string) (_ *schema.Key, _ *schema.User, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "GetKeyByToken",
		attribute.Int("token_length", len(strings.TrimSpace(token))),
	)
	defer func() { endSpan(err) }()

	// Strip the prefix from the token if needed
	if hook, ok := m.opt.hooks.(APIKeyHook); ok && hook != nil {
		if token_, err := hook.OnKeyValidate(ctx, token); err != nil {
			return nil, nil, err
		} else {
			token = token_
		}
	}

	var key schema.Key
	var user schema.User
	if err = m.PoolConn.Tx(ctx, func(conn pg.Conn) error {
		if err := conn.Get(ctx, &key, schema.KeyToken{Token: token, Query: "apikey.select"}); err != nil {
			return err
		} else if err := conn.Get(ctx, &user, schema.KeyToken{Token: token, Query: "apikey.user"}); err != nil {
			return err
		}
		return nil
	}); err != nil {
		err = dbErr(err)
		return nil, nil, err
	}
	return types.Ptr(key), types.Ptr(user), nil
}

func (m *Manager) GetKeyByID(ctx context.Context, id schema.KeyID, user *schema.UserID) (_ *schema.Key, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "GetKeyByID",
		attribute.String("key", id.String()),
	)
	defer func() { endSpan(err) }()

	var key schema.Key
	if err = m.PoolConn.Get(ctx, &key, schema.KeySelector{ID: id, User: user, Query: "apikey.get"}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(key), nil
}

func (m *Manager) UpdateKey(ctx context.Context, id schema.KeyID, user *schema.UserID, meta schema.KeyMeta) (_ *schema.Key, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "UpdateKey",
		attribute.String("key", id.String()),
		attribute.String("meta", meta.String()),
	)
	defer func() { endSpan(err) }()

	var key schema.Key
	if err = m.PoolConn.Update(ctx, &key, schema.KeySelector{ID: id, User: user, Query: "apikey.update"}, meta); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(key), nil
}

func (m *Manager) DeleteKey(ctx context.Context, id schema.KeyID, user *schema.UserID) (_ *schema.Key, err error) {
	ctx, endSpan := otel.StartSpan(m.tracer, ctx, "DeleteKey",
		attribute.String("key", id.String()),
	)
	defer func() { endSpan(err) }()

	var key schema.Key
	if err = m.PoolConn.Delete(ctx, &key, schema.KeySelector{ID: id, User: user, Query: "apikey.delete"}); err != nil {
		err = dbErr(err)
		return nil, err
	}
	return types.Ptr(key), nil
}
