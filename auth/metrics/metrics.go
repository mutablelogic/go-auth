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

package metrics

import (
	"context"
	"io"

	// Packages
	pg "github.com/mutablelogic/go-pg"
	metric "go.opentelemetry.io/otel/metric"
	errgroup "golang.org/x/sync/errgroup"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type Metrics struct {
	metric.Meter
	Conn    pg.Conn
	metrics []Metric
}

type Metric interface {
	// Register a metric
	Register(metric.Meter) error

	// Observe the metric
	Observe(context.Context, metric.Observer) error
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

func New(r io.Reader, meter metric.Meter, conn pg.PoolConn) (*Metrics, error) {
	// We read in the queries we use to generate the metrics
	queries, err := pg.NewQueries(r)
	if err != nil {
		return nil, err
	}

	// Return the metrics
	return &Metrics{
		Meter: meter,
		Conn:  conn.WithQueries(queries),
	}, nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - REGISTER

func (m *Metrics) Add(metric Metric) error {
	if err := metric.Register(m.Meter); err != nil {
		return err
	} else {
		m.metrics = append(m.metrics, metric)
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// PUBLIC METHODS - RUN

// Run metrics until the context is cancelled.
func (m *Metrics) Run(ctx context.Context) error {
	if _, err := m.Meter.RegisterCallback(func(ctx context.Context, observer metric.Observer) error {
		wg, errctx := errgroup.WithContext(ctx)
		for _, metric := range m.metrics {
			wg.Go(func() error {
				return metric.Observe(errctx, observer)
			})
		}
		return wg.Wait()
	}); err != nil {
		return err
	}

	// Wait for the context to be cancelled
	<-ctx.Done()

	// Return nil
	return nil
}
