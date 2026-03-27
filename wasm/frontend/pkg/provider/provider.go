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

package provider

import (
	"encoding/json"
	"fmt"
	"net/url"
	"sync"

	// Packages
	"github.com/djthorpe/go-wasmbuild/pkg/js"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

// QueryRequest represents a typed collection query that can be encoded into URL values.
type QueryRequest interface {
	Query() url.Values
}

// Provider fetches data from a remote source and returns typed async results.
type Provider[K any, M any, R any] interface {
	// Get fetches key and decodes the response as R.
	Get(key K, opts ...js.FetchOption) *Promise[R]

	// Post marshals body as JSON, posts to the configured resource path, and decodes the response as R.
	Post(body M, opts ...js.FetchOption) *Promise[R]

	// Patch marshals body as JSON, patches key, and decodes the response as R.
	Patch(key K, body M, opts ...js.FetchOption) *Promise[R]

	// Delete sends a DELETE to key and decodes any response body as R.
	Delete(key K, opts ...js.FetchOption) *Promise[R]

	// Key derives the resource key from a response value.
	Key(value R) (K, error)
}

// ListProvider fetches collection resources using a typed query request.
type ListProvider[Q QueryRequest, L any] interface {
	// List fetches the configured collection path with the encoded query request and decodes the response as L.
	List(query Q, opts ...js.FetchOption) *Promise[L]
}

// provider is the concrete Provider[K, M, R] implementation.
type provider[K any, M any, R any] struct {
	path  string
	base  *url.URL
	keyfn func(R) K
}

// listProvider is the concrete ListProvider[Q, L] implementation.
type listProvider[Q QueryRequest, L any] struct {
	path string
	base *url.URL
}

var _ Provider[any, any, any] = (*provider[any, any, any])(nil)
var _ ListProvider[queryRequest, any] = (*listProvider[queryRequest, any])(nil)

// Promise represents a typed asynchronous result.
type Promise[T any] struct {
	executor   func(resolve func(T), reject func(error))
	once       sync.Once
	settleOnce sync.Once
	done       chan struct{}
	value      T
	err        error
	mu         sync.Mutex
	callbacks  []func(T, error)
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// NewProvider creates a new provider with key type K, meta type M, response type R, and a resource path.
func NewProvider[K any, M any, R any](base *url.URL, path string, keyfn func(R) K) Provider[K, M, R] {
	if base == nil || path == "" {
		return nil
	}
	return &provider[K, M, R]{
		path:  path,
		base:  base,
		keyfn: keyfn,
	}
}

// NewListProvider creates a new list provider with query type Q, list response type L, and a collection path.
func NewListProvider[Q QueryRequest, L any](base *url.URL, path string) ListProvider[Q, L] {
	if base == nil || path == "" {
		return nil
	}
	return &listProvider[Q, L]{base: base, path: path}
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS

func (p *provider[K, M, R]) Get(key K, opts ...js.FetchOption) *Promise[R] {
	return p.do(pathWithKey(p.path, key), append([]js.FetchOption{js.WithMethod("GET")}, opts...)...)
}

func (p *provider[K, M, R]) Post(body M, opts ...js.FetchOption) *Promise[R] {
	requestOpts, err := withJSONBody(body, opts)
	if err != nil {
		return rejectPromise[R](err)
	}
	return p.do(p.path, append([]js.FetchOption{js.WithMethod("POST")}, requestOpts...)...)
}

func (p *provider[K, M, R]) Patch(key K, body M, opts ...js.FetchOption) *Promise[R] {
	requestOpts, err := withJSONBody(body, opts)
	if err != nil {
		return rejectPromise[R](err)
	}
	return p.do(pathWithKey(p.path, key), append([]js.FetchOption{js.WithMethod("PATCH")}, requestOpts...)...)
}

func (p *provider[K, M, R]) Delete(key K, opts ...js.FetchOption) *Promise[R] {
	return p.do(pathWithKey(p.path, key), append([]js.FetchOption{js.WithMethod("DELETE")}, opts...)...)
}

func (p *provider[K, M, R]) Key(value R) (K, error) {
	if p.keyfn == nil {
		return *new(K), fmt.Errorf("provider key function is not configured")
	}
	return p.keyfn(value), nil
}

func (p *listProvider[Q, L]) List(query Q, opts ...js.FetchOption) *Promise[L] {
	u := p.base.JoinPath(p.path)
	u.RawQuery = query.Query().Encode()
	return do[L](u, append([]js.FetchOption{js.WithMethod("GET")}, opts...)...)
}

///////////////////////////////////////////////////////////////////////////////
// PRIVATE METHODS

func (p *provider[K, M, R]) do(path string, opts ...js.FetchOption) *Promise[R] {
	u := p.base.JoinPath(path)
	return do[R](u, opts...)
}

func do[T any](u *url.URL, opts ...js.FetchOption) *Promise[T] {
	return newPromise(func(resolve func(T), reject func(error)) {
		js.Fetch(u.String(), opts...).Done(func(v js.Value, err error) {
			if err != nil {
				reject(err)
				return
			}
			resp := js.ResponseFrom(v)
			resp.Text().Done(func(tv js.Value, err error) {
				if err != nil {
					reject(err)
					return
				}
				body := tv.String()
				if body == "" {
					resolve(*new(T))
					return
				}
				var result T
				if err := json.Unmarshal([]byte(body), &result); err != nil {
					reject(err)
					return
				}
				resolve(result)
			})
		})
	})
}

type queryRequest struct{}

func (queryRequest) Query() url.Values {
	return url.Values{}
}

func pathWithKey[K any](path string, key K) string {
	return fmt.Sprintf("%s/%v", path, key)
}

func newPromise[T any](executor func(resolve func(T), reject func(error))) *Promise[T] {
	return &Promise[T]{
		executor: executor,
		done:     make(chan struct{}),
	}
}

func rejectPromise[T any](err error) *Promise[T] {
	return newPromise(func(resolve func(T), reject func(error)) {
		reject(err)
	})
}

func withJSONBody[T any](body T, opts []js.FetchOption) ([]js.FetchOption, error) {
	b, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	return append([]js.FetchOption{js.WithJSON(string(b))}, opts...), nil
}

func (p *Promise[T]) Done(fn func(T, error)) *Promise[T] {
	p.start()

	p.mu.Lock()
	if p.isSettled() {
		value, err := p.value, p.err
		p.mu.Unlock()
		fn(value, err)
		return p
	}
	p.callbacks = append(p.callbacks, fn)
	p.mu.Unlock()

	return p
}

func (p *Promise[T]) Wait() (T, error) {
	p.start()
	<-p.done
	return p.value, p.err
}

func (p *Promise[T]) start() {
	p.once.Do(func() {
		p.executor(p.resolve, p.reject)
	})
}

func (p *Promise[T]) resolve(value T) {
	p.settle(value, nil)
}

func (p *Promise[T]) reject(err error) {
	p.settle(*new(T), err)
}

func (p *Promise[T]) settle(value T, err error) {
	p.settleOnce.Do(func() {
		p.mu.Lock()
		p.value = value
		p.err = err
		callbacks := append([]func(T, error){}, p.callbacks...)
		p.callbacks = nil
		close(p.done)
		p.mu.Unlock()

		for _, fn := range callbacks {
			fn(value, err)
		}
	})
}

func (p *Promise[T]) isSettled() bool {
	select {
	case <-p.done:
		return true
	default:
		return false
	}
}
