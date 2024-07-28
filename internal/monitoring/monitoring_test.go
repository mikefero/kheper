// Copyright © 2024 Michael Fero
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package monitoring_test

import (
	"testing"
	"time"

	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/stretchr/testify/require"
)

func TestMonitoring(t *testing.T) {
	t.Parallel()

	t.Run("verify error occurs when open telemetry host is invalid", func(t *testing.T) {
		t.Parallel()

		m, err := monitoring.NewMonitoring(monitoring.Opts{
			OpenTelemetry: config.OpenTelemetry{
				Enabled:          true,
				Host:             "invalid host",
				Port:             4317,
				ServiceName:      "kheper",
				MetricInterval:   2 * time.Second,
				ShutdownInterval: 10 * time.Second,
			},
		})
		require.ErrorContains(t, err, "invalid open telemetry host: invalid host")
		require.Nil(t, m)
	})

	t.Run("verify error occurs when open telemetry port is invalid", func(t *testing.T) {
		t.Parallel()

		m, err := monitoring.NewMonitoring(monitoring.Opts{
			OpenTelemetry: config.OpenTelemetry{
				Enabled:          true,
				Host:             "kheper",
				Port:             0,
				ServiceName:      "kheper",
				MetricInterval:   2 * time.Second,
				ShutdownInterval: 10 * time.Second,
			},
		})
		require.ErrorContains(t, err, "invalid open telemetry port: 0")
		require.Nil(t, m)
	})

	t.Run("verify monitoring is created", func(t *testing.T) {
		t.Parallel()

		m, err := monitoring.NewMonitoring(monitoring.Opts{
			OpenTelemetry: config.OpenTelemetry{
				Enabled:          true,
				Host:             "localhost",
				Port:             4317,
				ServiceName:      "kheper",
				MetricInterval:   2 * time.Second,
				ShutdownInterval: 10 * time.Second,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, m)
	})

	t.Run("verify monitoring is created only once", func(t *testing.T) {
		t.Parallel()

		m, err := monitoring.NewMonitoring(monitoring.Opts{
			OpenTelemetry: config.OpenTelemetry{
				Enabled:          true,
				Host:             "localhost",
				Port:             4317,
				ServiceName:      "kheper",
				MetricInterval:   2 * time.Second,
				ShutdownInterval: 10 * time.Second,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, m)

		m2, err := monitoring.NewMonitoring(monitoring.Opts{
			OpenTelemetry: config.OpenTelemetry{
				Enabled:          false,
				Host:             "localhost",
				Port:             4317,
				ServiceName:      "kheper",
				MetricInterval:   2 * time.Second,
				ShutdownInterval: 10 * time.Second,
			},
		})
		require.NoError(t, err)
		require.NotNil(t, m)

		require.Equal(t, m, m2)
	})
}
