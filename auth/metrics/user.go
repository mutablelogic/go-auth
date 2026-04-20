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
	"fmt"

	// Packages
	pg "github.com/mutablelogic/go-pg"
	"go.opentelemetry.io/otel/attribute"
	metric "go.opentelemetry.io/otel/metric"
)

///////////////////////////////////////////////////////////////////////////////
// TYPES

type UserMetric struct {
	Status string
	Count  uint64
}

type UserMetrics struct {
	conn   pg.Conn
	metric metric.Int64ObservableGauge
	Body   []UserMetric
}

///////////////////////////////////////////////////////////////////////////////
// LIFECYCLE

// Register a metric
func (u *UserMetrics) Register(meter metric.Meter, conn pg.Conn) error {
	if users, err := meter.Int64ObservableGauge("users",
		metric.WithDescription("Number of users grouped by status"),
	); err != nil {
		return err
	} else {
		u.metric = users
		u.conn = conn
	}

	// Return success
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// SELECTOR

func (UserMetrics) Select(bind *pg.Bind, _ pg.Op) (string, error) {
	return bind.Query("metric.user"), nil
}

///////////////////////////////////////////////////////////////////////////////
// READER

func (u *UserMetrics) Scan(row pg.Row) error {
	var metric UserMetric
	if err := row.Scan(&metric.Status, &metric.Count); err != nil {
		return err
	} else {
		u.Body = append(u.Body, metric)
	}
	return nil
}

///////////////////////////////////////////////////////////////////////////////
// OBSERVER

// Observe the metric
func (u *UserMetrics) Observe(ctx context.Context, observer metric.Observer) error {
	u.Body = make([]UserMetric, 0, len(u.Body))
	if err := u.conn.List(ctx, u, UserMetrics{}); err != nil {
		return fmt.Errorf("query user metrics: %w", err)
	}
	for _, row := range u.Body {
		observer.ObserveInt64(u.metric, int64(row.Count), metric.WithAttributes(
			attribute.String("status", row.Status),
		))
	}
	return nil
}
