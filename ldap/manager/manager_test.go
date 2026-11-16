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

package manager_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	// Packages
	ldapv3 "github.com/go-ldap/ldap/v3"
	manager "github.com/mutablelogic/go-auth/ldap/manager"
	schema "github.com/mutablelogic/go-auth/ldap/schema"
	test "github.com/mutablelogic/go-auth/ldap/test"
	httpresponse "github.com/mutablelogic/go-server/pkg/httpresponse"
	assert "github.com/stretchr/testify/assert"
	require "github.com/stretchr/testify/require"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracetest "go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// The tests run against each directory in ldap/test, and are skipped with
// -short, other than those with test.Fake, which need a directory which
// doesn't answer, or fails, at a point

// TestMain runs the tests, then stops the directories' containers
func TestMain(m *testing.M) {
	test.Main(m)
}

func Test_Connect(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		assert.Equal(t, "127.0.0.1", m.Host())
		assert.NotZero(t, m.Port())
		assert.Equal(t, server.BindDN, m.User())

		whoami, err := m.WhoAmI(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, whoami)

		// A second Connect checks the connection, rather than connecting
		require.NoError(t, m.Connect(ctx))

		require.NoError(t, m.Disconnect(ctx))
		_, err = m.WhoAmI(ctx)
		assert.ErrorIs(t, err, httpresponse.ErrGatewayError)

		require.NoError(t, m.Connect(ctx))
		whoami, err = m.WhoAmI(ctx)
		require.NoError(t, err)
		assert.NotEmpty(t, whoami)
	})
}

func Test_WrongPassword(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, _ *manager.Manager) {
		other, err := manager.New(manager.WithUrl(server.URL), manager.WithBaseDN(server.BaseDN), manager.WithUser(server.BindDN), manager.WithPassword("wrong-password"), manager.WithSkipVerify())
		require.NoError(t, err)
		assert.ErrorIs(t, other.Connect(ctx), httpresponse.ErrNotAuthorized)

		// The connection was closed
		_, err = other.WhoAmI(ctx)
		assert.ErrorIs(t, err, httpresponse.ErrGatewayError)
	})
}

func Test_Run(t *testing.T) {
	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		require.NoError(t, m.Disconnect(ctx))

		runCtx, cancel := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- m.Run(runCtx, slogDiscard()) }()

		// Run connects
		connected := func() bool {
			_, err := m.WhoAmI(ctx)
			return err == nil
		}
		assert.Eventually(t, connected, server.ConnectTimeout, 100*time.Millisecond)

		// And disconnects when it's cancelled
		cancel()
		select {
		case err := <-done:
			require.NoError(t, err)
		case <-time.After(5 * time.Second):
			t.Fatal("timed out waiting for Run to return")
		}
		assert.False(t, connected())
	})
}

func Test_Trace(t *testing.T) {
	recorder := tracetest.NewSpanRecorder()
	tracer := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder)).Tracer("test")

	test.ForEach(t, func(t *testing.T, ctx context.Context, server test.Server, m *manager.Manager) {
		recorder.Reset()
		_, err := m.WhoAmI(ctx)
		require.NoError(t, err)
		require.NoError(t, m.Disconnect(ctx))
		_, err = m.WhoAmI(ctx)
		assert.ErrorIs(t, err, httpresponse.ErrGatewayError, "not connected")

		// Each method has a span, with the server, and never the password,
		// and the error when there is one
		spans := recorder.Ended()
		names := []string{}
		for _, span := range spans {
			names = append(names, span.Name())
			attrs := map[string]string{}
			for _, attr := range span.Attributes() {
				attrs[string(attr.Key)] = attr.Value.Emit()
				assert.NotContains(t, attr.Value.Emit(), server.BindPassword, span.Name())
			}
			assert.Equal(t, "127.0.0.1", attrs["server.address"], span.Name())
			assert.NotEmpty(t, attrs["server.port"], span.Name())
		}
		assert.Equal(t, []string{"ldapmanager.WhoAmI", "ldapmanager.Disconnect", "ldapmanager.WhoAmI"}, names)
		require.Len(t, spans, 3)
		assert.Equal(t, "Unset", spans[0].Status().Code.String())
		assert.Equal(t, "Error", spans[2].Status().Code.String())
	}, manager.WithTracer(tracer))
}

func Test_ConnectCancelled(t *testing.T) {
	// A directory which never answers a bind
	d := test.NewFake(t, false)
	d.Stall = func(op uint8, _ string) bool { return op == ldapv3.ApplicationBindRequest }
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)

	// The bind is abandoned when the context is cancelled
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	start := time.Now()
	err = m.Connect(ctx)
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.Less(t, time.Since(start), 5*time.Second)

	// The lock is free, and the manager isn't connected
	assert.NoError(t, m.Disconnect(context.Background()))
	_, err = m.WhoAmI(context.Background())
	assert.ErrorIs(t, err, httpresponse.ErrGatewayError)

	// Run returns when it's cancelled, though the bind hangs
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(ctx, slogDiscard()) }()
	time.Sleep(300 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run didn't return")
	}
}

func Test_WriteCancelled(t *testing.T) {
	// A directory which never answers an add
	d := test.NewFake(t, false)
	d.Stall = func(op uint8, _ string) bool { return op == ldapv3.ApplicationAddRequest }
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)

	// Run connects
	runCtx, stop := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- m.Run(runCtx, slogDiscard()) }()
	defer func() {
		stop()
		<-done
	}()

	// A write which isn't answered is abandoned when the context is
	// cancelled, which closes the connection. Until Run has connected,
	// it's not connected.
	attrs := schema.Attrs{"objectClass": {"organizationalUnit"}, "ou": {"a"}}
	require.Eventually(t, func() bool {
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()
		_, err := m.Create(ctx, "ou=a", attrs)
		return errors.Is(err, context.DeadlineExceeded)
	}, 5*time.Second, 10*time.Millisecond)
	assert.Equal(t, 1, d.Connections())

	// And Run reconnects at once, rather than at its next check
	assert.Eventually(t, func() bool { return d.Connections() == 2 }, 5*time.Second, 10*time.Millisecond)
}

func slogDiscard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func Test_SearchCancelled(t *testing.T) {
	// A search which isn't answered, and is cancelled, is the context's
	// error, not an entry which isn't found
	d := test.NewFake(t, false)
	d.Stall = func(op uint8, _ string) bool { return op == ldapv3.ApplicationSearchRequest }
	m, err := manager.New(manager.WithUrl(d.URL("ldap")), manager.WithBaseDN("dc=example,dc=test"))
	require.NoError(t, err)
	require.NoError(t, m.Connect(context.Background()))
	defer m.Disconnect(context.Background())

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	_, err = m.Get(ctx, "ou=a")
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.NotErrorIs(t, err, httpresponse.ErrNotFound)
}
