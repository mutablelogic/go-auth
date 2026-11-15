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

package env_test

import (
	"context"
	"encoding/json"
	"testing"

	// Packages
	env "github.com/mutablelogic/go-auth/credential/env"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func Test_Trace(t *testing.T) {
	ctx := context.Background()
	t.Setenv("GOAUTH_TEST_TRACE", "env-secret")
	recorder := tracetest.NewSpanRecorder()
	provider := env.New(env.WithTracer(sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")))

	_, err := provider.Get(ctx, "GOAUTH_TEST_TRACE")
	require.NoError(t, err)
	_, err = provider.Expand(ctx, "literal-secret $GOAUTH_TEST_TRACE")
	require.NoError(t, err)
	assert.Error(t, provider.Set(ctx, "GOAUTH_TEST_TRACE", json.RawMessage(`"x"`)))

	names := make(map[string]bool)
	for _, span := range recorder.Ended() {
		names[span.Name()] = true
		for _, attr := range span.Attributes() {
			assert.NotContains(t, attr.Value.Emit(), "env-secret", span.Name())
			assert.NotContains(t, attr.Value.Emit(), "literal-secret", span.Name())
			if span.Name() == "credential.env.Expand" && attr.Key == "keys" {
				assert.Equal(t, []string{"GOAUTH_TEST_TRACE"}, attr.Value.AsStringSlice())
			}
		}
	}
	assert.Equal(t, map[string]bool{"credential.env.Get": true, "credential.env.Expand": true, "credential.env.Set": true}, names)
}
