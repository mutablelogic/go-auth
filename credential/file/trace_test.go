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

package file_test

import (
	"context"
	"encoding/json"
	"testing"

	// Packages
	file "github.com/mutablelogic/go-auth/credential/file"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func Test_Trace(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GOAUTH_TEST_TRACE_ENV", "env-secret")
	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")

	// WithEnv is before WithTracer, and the environment is still traced
	mgr, err := file.New(t.TempDir(), file.WithEnv(), file.WithPassphrase(1, passphrase), file.WithTracer(tracer))
	require.NoError(t, err)
	require.NoError(t, mgr.Set(ctx, "trace_user", json.RawMessage(`"file-secret"`)))
	_, err = mgr.Get(ctx, "trace_user")
	require.NoError(t, err)
	got, err := mgr.Expand(ctx, "literal-secret $trace_user ${GOAUTH_TEST_TRACE_ENV}")
	require.NoError(t, err)
	assert.Equal(t, "literal-secret file-secret env-secret", got)

	spans := make(map[string]sdktrace.ReadOnlySpan)
	for _, span := range recorder.Ended() {
		spans[span.Name()] = span

		// No secret is recorded
		for _, attr := range span.Attributes() {
			for _, secret := range []string{"literal-secret", "file-secret", "env-secret"} {
				assert.NotContains(t, attr.Value.Emit(), secret, span.Name())
			}
		}
	}
	for _, name := range []string{"credential.file.New", "credential.file.Set", "credential.file.Get", "credential.file.Expand", "credential.env.Expand"} {
		assert.Contains(t, spans, name)
	}

	// The Expand span records the keys used, and is the parent of the
	// environment's span
	expand := spans["credential.file.Expand"]
	require.NotNil(t, expand)
	for _, attr := range expand.Attributes() {
		if attr.Key == "keys" {
			assert.Equal(t, []string{"GOAUTH_TEST_TRACE_ENV", "trace_user"}, attr.Value.AsStringSlice())
		}
	}
	require.NotNil(t, spans["credential.env.Expand"])
	assert.Equal(t, expand.SpanContext().SpanID(), spans["credential.env.Expand"].Parent().SpanID())
	for _, name := range []string{"credential.file.Set", "credential.file.Get"} {
		var key string
		for _, attr := range spans[name].Attributes() {
			if attr.Key == "key" {
				key = attr.Value.AsString()
			}
		}
		assert.Equal(t, "trace_user", key, name)
	}
}
