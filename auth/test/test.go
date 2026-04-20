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

package test

import (
	"context"
	"sync"
	"testing"

	// Packages
	manager "github.com/mutablelogic/go-auth/auth/manager"
	pg "github.com/mutablelogic/go-pg"
	test "github.com/mutablelogic/go-pg/pkg/test"
)

///////////////////////////////////////////////////////////////////////////////
// GLOBALS

var (
	shared      *manager.Manager
	testCancels cancelRegistry
)

type cancelRegistry struct {
	mu      sync.Mutex
	cancels map[*testing.T]context.CancelFunc
}

func (r *cancelRegistry) Store(t *testing.T, cancel context.CancelFunc) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancels == nil {
		r.cancels = make(map[*testing.T]context.CancelFunc)
	}
	r.cancels[t] = cancel
}

func (r *cancelRegistry) LoadAndDelete(t *testing.T) (context.CancelFunc, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.cancels == nil {
		return nil, false
	}
	cancel, ok := r.cancels[t]
	if ok {
		delete(r.cancels, t)
	}
	return cancel, ok
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// Main is the test main function for auth manager tests. It starts up a container and runs the tests,
// providing a manager instance to each test.
func Main(m *testing.M, setup func(*manager.Manager) (func(), error), opts ...manager.Opt) {
	test.Main(m, func(pool pg.PoolConn) (func(), error) {
		mgr, err := manager.New(context.Background(), pool, "manager", "test", opts...)
		if err != nil {
			return nil, err
		}
		shared = mgr

		teardown := func() {}
		if setup != nil {
			if teardown_, err := setup(mgr); err != nil {
				return nil, err
			} else if teardown_ != nil {
				teardown = teardown_
			}
		}

		runCtx, cancel := context.WithCancel(context.Background())
		runDone := make(chan error, 1)
		go func() {
			runDone <- mgr.Run(runCtx)
		}()
		return func() {
			cancel()
			if err := <-runDone; err != nil {
				panic(err)
			}
			shared = nil
			teardown()
		}, nil
	})
}

// Begin returns the shared test manager and a per-test context.
func Begin(t *testing.T) (*manager.Manager, context.Context) {
	t.Helper()
	if shared == nil {
		t.Fatal("test manager is not initialized; call auth/test.Main from TestMain")
	}
	base := context.Background()
	baseCancel := func() {}
	if deadline, ok := t.Deadline(); ok {
		base, baseCancel = context.WithDeadline(base, deadline)
	}
	ctx, cancel := context.WithCancel(base)
	stop := func() {
		cancel()
		baseCancel()
	}
	testCancels.Store(t, context.CancelFunc(stop))
	t.Cleanup(func() {
		if cancel, ok := testCancels.LoadAndDelete(t); ok {
			cancel()
		}
	})
	return shared, ctx
}

// End releases the per-test context created by Begin.
func End(t *testing.T) {
	t.Helper()
	if cancel, ok := testCancels.LoadAndDelete(t); ok {
		cancel()
	}
}
