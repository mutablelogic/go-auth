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

package certmanager

import (
	"context"
	"io"
	"log/slog"
	"sync"
	"time"

	// Packages
	clientpkg "github.com/mutablelogic/go-client"
	trace "go.opentelemetry.io/otel/trace"
)

type fakeCmd struct {
	ctx      context.Context
	endpoint string
	store    map[string]any
	mu       sync.Mutex
	logger   *slog.Logger
	debug    bool
}

func newFakeCmd(endpoint string) *fakeCmd {
	return &fakeCmd{
		ctx:      context.Background(),
		endpoint: endpoint,
		store:    make(map[string]any),
		logger:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func (f *fakeCmd) Name() string             { return "test" }
func (f *fakeCmd) Description() string      { return "test" }
func (f *fakeCmd) Version() string          { return "test" }
func (f *fakeCmd) Context() context.Context { return f.ctx }
func (f *fakeCmd) Logger() *slog.Logger     { return f.logger }
func (f *fakeCmd) Tracer() trace.Tracer     { return nil }
func (f *fakeCmd) ClientEndpoint() (string, []clientpkg.ClientOpt, error) {
	return f.endpoint, nil, nil
}
func (f *fakeCmd) Get(key string) any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.store[key]
}
func (f *fakeCmd) GetString(key string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	value, _ := f.store[key].(string)
	return value
}
func (f *fakeCmd) Set(key string, value any) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if value == nil {
		delete(f.store, key)
	} else {
		f.store[key] = value
	}
	return nil
}
func (f *fakeCmd) Keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	keys := make([]string, 0, len(f.store))
	for key := range f.store {
		keys = append(keys, key)
	}
	return keys
}
func (f *fakeCmd) IsTerm() bool               { return false }
func (f *fakeCmd) IsDebug() bool              { return f.debug }
func (f *fakeCmd) HTTPAddr() string           { return "" }
func (f *fakeCmd) HTTPPrefix() string         { return "" }
func (f *fakeCmd) HTTPOrigin() string         { return "" }
func (f *fakeCmd) HTTPTimeout() time.Duration { return 0 }
