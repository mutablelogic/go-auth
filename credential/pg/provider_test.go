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

package pg_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	// Packages
	auth "github.com/mutablelogic/go-auth"
	authcredential "github.com/mutablelogic/go-auth/credential"
	credential "github.com/mutablelogic/go-auth/credential/pg"
	schema "github.com/mutablelogic/go-auth/credential/pg/schema"
	test "github.com/mutablelogic/go-auth/credential/pg/test"
	pgpkg "github.com/mutablelogic/go-pg"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func TestCredentialProvider(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)

	mustCreate(t, ctx, manager, "provider_user", "admin")
	mustCreate(t, ctx, manager, "provider_pass", "hunter2")
	mustCreate(t, ctx, manager, "provider-dash", "dashed")
	mustCreate(t, ctx, manager, "provider_object", map[string]string{"user": "admin"})
	provider := manager.GetCredentialProvider()

	t.Run("Expand", func(t *testing.T) {
		for value, want := range map[string]string{
			"no placeholders":  "no placeholders",
			"":                 "",
			"$provider_user":   "admin",
			"${provider_user}": "admin",
			"https://${provider_user}:${provider_pass}@host": "https://admin:hunter2@host",
			"$provider_user/$provider_user":                  "admin/admin",
			"${provider-dash}":                               "dashed",
		} {
			got, err := provider.Expand(ctx, value)
			require.NoError(t, err, "value %q", value)
			assert.Equal(t, want, got, "value %q", value)
		}
	})

	t.Run("NotFound", func(t *testing.T) {
		got, err := provider.Expand(ctx, "user=${provider_user} key=${provider_missing}")
		assert.ErrorIs(t, err, auth.ErrNotFound)
		assert.ErrorContains(t, err, "provider_missing")
		assert.Empty(t, got, "no partly expanded value")
	})

	t.Run("NotString", func(t *testing.T) {
		_, err := provider.Expand(ctx, "${provider_object}")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("InvalidPlaceholder", func(t *testing.T) {
		// "$1" is a placeholder which isn't a valid key, and "$provider-dash"
		// stops at the "-", so is the key "provider", which doesn't exist
		_, err := provider.Expand(ctx, "$1")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
		// os.Expand removes the invalid syntax "${}"
		got, err := provider.Expand(ctx, "a${}b")
		require.NoError(t, err)
		assert.Equal(t, "ab", got)
		_, err = provider.Expand(ctx, "$provider-dash")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("Get", func(t *testing.T) {
		// A credential is returned as JSON, whatever its type
		got, err := provider.Get(ctx, "provider_user")
		require.NoError(t, err)
		assert.JSONEq(t, `"admin"`, string(got))
		got, err = provider.Get(ctx, "provider_object")
		require.NoError(t, err)
		assert.JSONEq(t, `{"user":"admin"}`, string(got))

		// A credential which doesn't exist, or an invalid key, is an error
		_, err = provider.Get(ctx, "provider_missing")
		assert.ErrorIs(t, err, auth.ErrNotFound)
		_, err = provider.Get(ctx, "not a key")
		assert.ErrorIs(t, err, auth.ErrBadParameter)
	})

	t.Run("Set", func(t *testing.T) {
		// A credential is stored, and replaced, and can then be expanded
		require.NoError(t, provider.Set(ctx, "provider_token", json.RawMessage(`{"refresh_token":"abc"}`)))
		got, err := provider.Get(ctx, "provider_token")
		require.NoError(t, err)
		assert.JSONEq(t, `{"refresh_token":"abc"}`, string(got))
		require.NoError(t, provider.Set(ctx, "provider_token", json.RawMessage(`"xyz"`)))
		expanded, err := provider.Expand(ctx, "${provider_token}")
		require.NoError(t, err)
		assert.Equal(t, "xyz", expanded)

		// A value which isn't JSON, or an invalid key, is an error
		assert.ErrorIs(t, provider.Set(ctx, "provider_token", json.RawMessage(`not json`)), auth.ErrBadParameter)
		assert.ErrorIs(t, provider.Set(ctx, "not a key", json.RawMessage(`"x"`)), auth.ErrBadParameter)
	})

	t.Run("Cancelled", func(t *testing.T) {
		// Lookups use the context
		cancelled, cancel := context.WithCancel(ctx)
		cancel()
		_, err := provider.Expand(cancelled, "${provider_user}")
		assert.ErrorIs(t, err, context.Canceled)
	})
}

func TestCredentialProviderTrace(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)
	mustCreate(t, ctx, manager, "trace_user", "admin")
	mustCreate(t, ctx, manager, "trace_pass", "hunter2")

	// A manager on the same schema, which records its spans
	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")
	traced, err := credential.New(ctx, manager.PoolConn, credential.WithSchema(test.Schema()), credential.WithPassphrase(test.PassphraseVersion, test.Passphrase), credential.WithTracer(tracer))
	require.NoError(t, err)

	got, err := traced.GetCredentialProvider().Expand(ctx, "literal-secret ${trace_user}:${trace_pass} $trace_user")
	require.NoError(t, err)
	assert.Equal(t, "literal-secret admin:hunter2 admin", got)

	// The Expand span records the keys used, but not the value, and is the
	// parent of the spans which read the credentials
	var expand sdktrace.ReadOnlySpan
	reads := 0
	for _, span := range recorder.Ended() {
		switch span.Name() {
		case "credential.pg.Expand":
			expand = span
		case "credential.pg.GetCredentialWithoutPassphrase":
			reads++
		}
	}
	require.NotNil(t, expand)
	assert.Equal(t, 2, reads, "each credential is read once")
	var keys []string
	for _, attr := range expand.Attributes() {
		assert.NotContains(t, attr.Value.Emit(), "literal-secret")
		if attr.Key == "keys" {
			keys = attr.Value.AsStringSlice()
		}
	}
	assert.Equal(t, []string{"trace_pass", "trace_user"}, keys)
	for _, span := range recorder.Ended() {
		if span.Name() == "credential.pg.GetCredentialWithoutPassphrase" {
			assert.Equal(t, expand.SpanContext().SpanID(), span.Parent().SpanID())
		}
	}
}

func TestNullProvider(t *testing.T) {
	manager, ctx := test.Begin(t)
	defer test.End(t)
	mustCreate(t, ctx, manager, "null_user", "admin")

	// A manager without a passphrase can't decrypt credentials, so returns
	// the null provider
	none, err := credential.New(ctx, manager.PoolConn, credential.WithSchema(test.Schema()))
	require.NoError(t, err)

	for name, provider := range map[string]authcredential.CredentialProvider{
		"NullProvider": credential.NullProvider(),
		"NoPassphrase": none.GetCredentialProvider(),
	} {
		t.Run(name, func(t *testing.T) {
			// A value without placeholders is unchanged
			got, err := provider.Expand(ctx, "file://media/mnt/media")
			require.NoError(t, err)
			assert.Equal(t, "file://media/mnt/media", got)

			// A placeholder is an error, even for a credential which exists
			got, err = provider.Expand(ctx, "user=${null_user}")
			assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
			assert.ErrorContains(t, err, "null_user")
			assert.Empty(t, got)

			// As is getting or storing a credential
			_, err = provider.Get(ctx, "null_user")
			assert.ErrorIs(t, err, auth.ErrServiceUnavailable)
			assert.ErrorContains(t, err, "null_user")
			assert.ErrorIs(t, provider.Set(ctx, "null_token", json.RawMessage(`"x"`)), auth.ErrServiceUnavailable)
		})
	}
}

func Test_WithEnv(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)
	schemaName := test.IsolatedSchema(t)

	t.Setenv("GOAUTH_TEST_ENV_ONLY", "from-env")
	t.Setenv("GOAUTH_TEST_ENV_NUMBER", "123")
	t.Setenv("GOAUTH_TEST_STORED", "from-env")

	mgr, err := credential.New(ctx, test.Pool(), credential.WithSchema(schemaName), credential.WithPassphrase(test.PassphraseVersion, test.Passphrase), credential.WithEnv())
	require.NoError(t, err)
	_, err = mgr.CreateCredential(ctx, schema.CredentialCreate{
		CredentialKey: schema.CredentialKey{Key: "GOAUTH_TEST_STORED"},
		Credentials:   "from-db",
	})
	require.NoError(t, err)
	provider := mgr.GetCredentialProvider()

	t.Run("GetStored", func(t *testing.T) {
		// A stored credential is used before the environment
		value, err := provider.Get(ctx, "GOAUTH_TEST_STORED")
		assert.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"from-db"`), value)
	})

	t.Run("GetEnv", func(t *testing.T) {
		value, err := provider.Get(ctx, "GOAUTH_TEST_ENV_ONLY")
		assert.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"from-env"`), value)
	})

	t.Run("GetMissing", func(t *testing.T) {
		_, err := provider.Get(ctx, "GOAUTH_TEST_MISSING")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("Expand", func(t *testing.T) {
		// An environment variable is expanded as it is, even when it's JSON
		value, err := provider.Expand(ctx, "$GOAUTH_TEST_STORED ${GOAUTH_TEST_ENV_ONLY} $GOAUTH_TEST_ENV_NUMBER")
		assert.NoError(t, err)
		assert.Equal(t, "from-db from-env 123", value)
	})

	t.Run("ExpandMissing", func(t *testing.T) {
		_, err := provider.Expand(ctx, "$GOAUTH_TEST_MISSING")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})

	t.Run("Set", func(t *testing.T) {
		// Credentials are still stored in the database
		assert.NoError(t, provider.Set(ctx, "GOAUTH_TEST_ENV_ONLY", json.RawMessage(`"from-set"`)))
		value, err := provider.Get(ctx, "GOAUTH_TEST_ENV_ONLY")
		assert.NoError(t, err)
		assert.Equal(t, json.RawMessage(`"from-set"`), value)
	})

	t.Run("NoPassphrase", func(t *testing.T) {
		// Without a passphrase, every credential is read from the environment
		mgr, err := credential.New(ctx, test.Pool(), credential.WithSchema(schemaName), credential.WithEnv())
		require.NoError(t, err)
		provider := mgr.GetCredentialProvider()
		value, err := provider.Expand(ctx, "$GOAUTH_TEST_STORED")
		assert.NoError(t, err)
		assert.Equal(t, "from-env", value)
		assert.ErrorIs(t, provider.Set(ctx, "GOAUTH_TEST_STORED", json.RawMessage(`"x"`)), auth.ErrNotImplemented)
	})

	t.Run("WithoutEnv", func(t *testing.T) {
		// Without WithEnv, the environment isn't read
		mgr, err := credential.New(ctx, test.Pool(), credential.WithSchema(schemaName), credential.WithPassphrase(test.PassphraseVersion, test.Passphrase))
		require.NoError(t, err)
		_, err = mgr.GetCredentialProvider().Get(ctx, "GOAUTH_TEST_ENV_ONLY_UNSET")
		assert.ErrorIs(t, err, auth.ErrNotFound)
		_, err = mgr.GetCredentialProvider().Expand(ctx, "$GOAUTH_TEST_ENV_NUMBER")
		assert.ErrorIs(t, err, auth.ErrNotFound)
	})
}

func Test_List(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)
	t.Setenv("GOAUTH_TEST_LIST_ENV", "from-env")
	mgr := test.IsolatedManager(t, credential.WithEnv())
	provider, ok := mgr.GetCredentialProvider().(authcredential.CredentialManager)
	require.True(t, ok)

	// Empty, and the environment isn't listed
	list, err := provider.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list)

	// More credentials than a page, in key order
	for i := range schema.CredentialListLimit + 5 {
		_, err := mgr.CreateCredential(ctx, schema.CredentialCreate{
			CredentialKey: schema.CredentialKey{Key: fmt.Sprintf("key_%03d", i)},
			Credentials:   "value",
		})
		require.NoError(t, err)
	}
	list, err = provider.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, schema.CredentialListLimit+5)
	assert.Equal(t, "key_000", list[0].Key)
	assert.Equal(t, fmt.Sprintf("key_%03d", schema.CredentialListLimit+4), list[len(list)-1].Key)
	assert.False(t, list[0].UpdatedAt.IsZero())
}

func Test_DeleteRotate(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)
	schemaName := test.IsolatedSchema(t)
	v1 := test.SchemaManager(t, schemaName)
	provider := v1.GetCredentialProvider().(authcredential.CredentialManager)
	rotator := v1.GetCredentialProvider().(authcredential.CredentialRotator)
	require.NoError(t, provider.Set(ctx, "key", json.RawMessage(`"value"`)))

	// Already the latest passphrase
	assert.ErrorIs(t, rotator.Rotate(ctx, "key"), auth.ErrNotModified)

	// With a new passphrase, it's re-encrypted, and can be read with only
	// the new passphrase
	v2 := test.SchemaManager(t, schemaName, credential.WithPassphrase(test.PassphraseVersion+1, "second passphrase"))
	require.NoError(t, v2.GetCredentialProvider().(authcredential.CredentialRotator).Rotate(ctx, "key"))
	only2, err := credential.New(ctx, test.Pool(), credential.WithSchema(schemaName), credential.WithPassphrase(test.PassphraseVersion+1, "second passphrase"))
	require.NoError(t, err)
	got, err := only2.GetCredentialProvider().Get(ctx, "key")
	require.NoError(t, err)
	assert.Equal(t, json.RawMessage(`"value"`), got)

	// Delete
	assert.ErrorIs(t, rotator.Rotate(ctx, "missing"), auth.ErrNotFound)
	require.NoError(t, provider.Delete(ctx, "key"))
	assert.ErrorIs(t, provider.Delete(ctx, "key"), auth.ErrNotFound)
	_, err = provider.Get(ctx, "key")
	assert.ErrorIs(t, err, auth.ErrNotFound)
}

func Test_Describe(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)
	mgr := test.IsolatedManager(t)
	provider := mgr.GetCredentialProvider().(authcredential.CredentialManager)
	require.NoError(t, provider.Set(ctx, "token", json.RawMessage(`"secret"`)))
	before, err := mgr.GetCredentialMeta(ctx, schema.CredentialKey{Key: "token"})
	require.NoError(t, err)

	// The description is listed, and doesn't change when it was updated
	require.NoError(t, provider.Describe(ctx, "token", "  The API token  "))
	list, err := provider.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, "The API token", list[0].Description)
	assert.Equal(t, before.UpdatedAt, list[0].UpdatedAt)
	meta, err := mgr.GetCredentialMeta(ctx, schema.CredentialKey{Key: "token"})
	require.NoError(t, err)
	assert.Equal(t, "The API token", meta.Description)

	// Replacing the value keeps it, and an empty description removes it
	require.NoError(t, provider.Set(ctx, "token", json.RawMessage(`"new"`)))
	list, err = provider.List(ctx)
	require.NoError(t, err)
	assert.Equal(t, "The API token", list[0].Description)
	require.NoError(t, provider.Describe(ctx, "token", ""))
	list, err = provider.List(ctx)
	require.NoError(t, err)
	assert.Empty(t, list[0].Description)

	assert.ErrorIs(t, provider.Describe(ctx, "missing", "x"), auth.ErrNotFound)
}

func Test_Notify(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)
	schemaName := test.IsolatedSchema(t)
	mgr := test.SchemaManager(t, schemaName, credential.WithChannel("credential_test"))
	provider := mgr.GetCredentialProvider().(authcredential.CredentialManager)

	// Listen on the channel
	notifications, err := test.Pool().Subscribe(ctx, "credential_test")
	require.NoError(t, err)
	next := func() map[string]string {
		t.Helper()
		select {
		case n := <-notifications:
			var change map[string]string
			require.NoError(t, json.Unmarshal(n.Payload, &change))
			assert.NotContains(t, string(n.Payload), "secret", "the value isn't notified")
			return change
		case <-time.After(5 * time.Second):
			t.Fatal("no notification")
			return nil
		}
	}

	// Each change is notified, by its key, as go-pg's pgbroadcaster publishes
	require.NoError(t, provider.Set(ctx, "token", json.RawMessage(`"secret"`)))
	assert.Equal(t, map[string]string{"action": "create", "schema": schemaName, "table": "credential", "row": "token"}, next())
	require.NoError(t, provider.Set(ctx, "token", json.RawMessage(`"secret2"`)))
	assert.Equal(t, "update", next()["action"])
	require.NoError(t, provider.Describe(ctx, "token", "described"))
	assert.Equal(t, "update", next()["action"])
	require.NoError(t, provider.Delete(ctx, "token"))
	assert.Equal(t, map[string]string{"action": "delete", "schema": schemaName, "table": "credential", "row": "token"}, next())

	// Without a channel, the trigger is dropped
	_ = test.SchemaManager(t, schemaName)
	var triggers []string
	require.NoError(t, test.Pool().List(ctx, &triggerList{&triggers}, triggerQuery{schemaName}))
	assert.Empty(t, triggers)
}

// triggerQuery lists the triggers on a schema's credential table
type triggerQuery struct{ schema string }

func (q triggerQuery) Select(bind *pgpkg.Bind, _ pgpkg.Op) (string, error) {
	bind.Set("trigger_schema", q.schema)
	return `SELECT tgname FROM pg_trigger T JOIN pg_class C ON C.oid = T.tgrelid JOIN pg_namespace N ON N.oid = C.relnamespace WHERE N.nspname = @trigger_schema AND C.relname = 'credential' AND NOT T.tgisinternal`, nil
}

type triggerList struct{ names *[]string }

func (l *triggerList) Scan(row pgpkg.Row) error {
	var name string
	if err := row.Scan(&name); err != nil {
		return err
	}
	*l.names = append(*l.names, name)
	return nil
}

func Test_ListRotate(t *testing.T) {
	_, ctx := test.Begin(t)
	defer test.End(t)
	schemaName := test.IsolatedSchema(t)
	v1 := test.SchemaManager(t, schemaName).GetCredentialProvider().(authcredential.CredentialManager)
	require.NoError(t, v1.Set(ctx, "old", json.RawMessage(`"x"`)))
	list, err := v1.List(ctx)
	require.NoError(t, err)
	assert.False(t, list[0].Rotate, "it uses the latest passphrase")

	// With a newer passphrase, it needs rotating, until it's rotated
	v2 := test.SchemaManager(t, schemaName, credential.WithPassphrase(test.PassphraseVersion+1, "second passphrase")).GetCredentialProvider().(authcredential.CredentialManager)
	require.NoError(t, v2.Set(ctx, "new", json.RawMessage(`"y"`)))
	list, err = v2.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.False(t, list[0].Rotate)
	assert.True(t, list[1].Rotate)
	require.NoError(t, v2.(authcredential.CredentialRotator).Rotate(ctx, "old"))
	list, err = v2.List(ctx)
	require.NoError(t, err)
	assert.False(t, list[1].Rotate)
}
