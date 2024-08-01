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
package monitoring

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/utils"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/embedded"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.4.0"
	"go.uber.org/zap"
)

const name = "github.com/mikefero/kheper"

var (
	// Tracer is the global tracer for Kheper.
	Tracer = otel.Tracer(name)

	singleton *Monitoring
	once      sync.Once
)

// Monitoring is a struct that contains all the metrics that are being collected
// by Kheper.
type Monitoring struct {
	// HostConnectionGauge is the number of connections per host.
	HostConnectionGauge metric.Int64Gauge
	// GroupConnectionGauge is the number of connections per group.
	GroupConnectionGauge metric.Int64Gauge
	// ConnectionGauge is the total number of connections.
	ConnectionGauge metric.Int64Gauge
	// DisconnectionErrorCount is the number of disconnection errors.
	DisconnectionErrorCount metric.Int64Counter
	// ReadMessageCount is the number of read messages.
	ReadMessageCount metric.Int64Counter
	// ReadMessageErrorCount is the number of read message errors.
	ReadMessageErrorCount metric.Int64Counter
	// ReadMessagePanicCount is the number of read message panics.
	ReadMessagePanicCount metric.Int64Counter
	// PingCount is the number of pings.
	PingCount metric.Int64Counter
	// PongCount is the number of pong messages.
	PongCount metric.Int64Counter
	// UncompressedSize is the size of the uncompressed message.
	UncompressedSize metric.Float64Gauge
	// CompressedSize is the size of the compressed message.
	CompressedSize metric.Float64Gauge
	// RetryConnectionCount is the number of retry connection attempts.
	RetryConnectionCount metric.Int64Counter
	// MissingRequiredPayloadEntities is the number of nodes that are missing
	// required payload entities.
	MissingRequiredPayloadEntities metric.Int64Counter

	shutdown func(ctx context.Context, logger *zap.Logger)
	logger   *zap.Logger
}

type Opts struct {
	OpenTelemetry config.OpenTelemetry
	Logger        *zap.Logger
}

type NoopInt64Gauge struct {
	embedded.Int64Gauge
}

func (NoopInt64Gauge) Record(_ context.Context, _ int64, _ ...metric.RecordOption) {}

type NoopInt64Counter struct {
	embedded.Int64Counter
}

func (NoopInt64Counter) Add(_ context.Context, _ int64, _ ...metric.AddOption) {}

type NoopFloat64Gauge struct {
	embedded.Float64Gauge
}

func (NoopFloat64Gauge) Record(_ context.Context, _ float64, _ ...metric.RecordOption) {}

// NewMonitoring creates a new monitoring instance for all the metrics that
// are being collected by Kheper. This function will create a no-op instance
// if OpenTelemetry is not enabled. This function is safe to call multiple times
// and will only create the monitoring instance once.
func NewMonitoring(opts Opts) (*Monitoring, error) {
	if opts.OpenTelemetry.Enabled {
		if err := utils.ValidateHostname(opts.OpenTelemetry.Host); err != nil {
			return nil, fmt.Errorf("invalid open telemetry host: %s", opts.OpenTelemetry.Host)
		}
		if err := utils.ValidatePort(opts.OpenTelemetry.Port); err != nil {
			return nil, fmt.Errorf("invalid open telemetry port: %d", opts.OpenTelemetry.Port)
		}
	}

	var err error
	once.Do(func() {
		// Create a no-op monitoring instance if OpenTelemetry is not enabled
		if !opts.OpenTelemetry.Enabled {
			singleton = &Monitoring{
				HostConnectionGauge:            NoopInt64Gauge{},
				GroupConnectionGauge:           NoopInt64Gauge{},
				ConnectionGauge:                NoopInt64Gauge{},
				DisconnectionErrorCount:        NoopInt64Counter{},
				ReadMessageCount:               NoopInt64Counter{},
				ReadMessageErrorCount:          NoopInt64Counter{},
				ReadMessagePanicCount:          NoopInt64Counter{},
				PingCount:                      NoopInt64Counter{},
				PongCount:                      NoopInt64Counter{},
				UncompressedSize:               NoopFloat64Gauge{},
				CompressedSize:                 NoopFloat64Gauge{},
				RetryConnectionCount:           NoopInt64Counter{},
				MissingRequiredPayloadEntities: NoopInt64Counter{},
				shutdown:                       func(_ context.Context, _ *zap.Logger) {},
			}
			return
		}

		// Initialize the OpenTelemetry provider
		shutdown, mp, oErr := initOtelProvider(opts.OpenTelemetry)
		if oErr != nil {
			err = fmt.Errorf("failed to create OTLP trace exporter: %w", err)
			return
		}
		serviceName := strings.ToLower(opts.OpenTelemetry.ServiceName)
		meter := mp.Meter(name)

		// Create the name grouped connection count gauge
		hostConnectionGauge, mErr := meter.Int64Gauge(
			fmt.Sprintf("%s_host_connection_count", serviceName),
			metric.WithDescription("total number of connections per host"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create name connection count metric: %w", err)
			return
		}

		// Create the group connection count gauge
		groupConnectionGauge, mErr := meter.Int64Gauge(
			fmt.Sprintf("%s_group_connection_count", serviceName),
			metric.WithDescription("total number of connections per group"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create group connection count metric: %w", err)
			return
		}

		// Create the total connection count gauge
		connectionGauge, mErr := meter.Int64Gauge(
			fmt.Sprintf("%s_total_connection_count", serviceName),
			metric.WithDescription("total number of connections"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create total connection count metric: %w", err)
			return
		}

		// Create the disconnection error count counter
		disconnectionErrorCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_disconnection_error_count", serviceName),
			metric.WithDescription("number of disconnection errors"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create disconnection error count metric: %w", err)
			return
		}

		// Create the read message count counter
		readMessageCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_read_message_count", serviceName),
			metric.WithDescription("number of read messages"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create read message count metric: %w", err)
			return
		}

		// Create the read message error count counter
		readMessageErrorCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_read_message_error_count", serviceName),
			metric.WithDescription("number of read message errors"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create read message error count metric: %w", err)
			return
		}

		// Create the read message panic count counter
		readMessagePanicCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_read_message_panic_count", serviceName),
			metric.WithDescription("number of read message panics"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create read message panic count metric: %w", err)
			return
		}

		// Create the ping count counter
		pingCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_ping_count", serviceName),
			metric.WithDescription("number of pings"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create ping count metric: %w", err)
			return
		}

		// Create the pong count counter
		pongCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_pong_count", serviceName),
			metric.WithDescription("number of pong messages"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create pong count metric: %w", err)
			return
		}

		// Create the uncompressed size gauge
		uncompressedSize, mErr := meter.Float64Gauge(
			fmt.Sprintf("%s_uncompressed_size", serviceName),
			metric.WithDescription("size of uncompressed message"),
			metric.WithUnit("kB"))
		if mErr != nil {
			err = fmt.Errorf("failed to create uncompressed size metric: %w", err)
			return
		}

		// Create the compressed size gauge
		compressedSize, mErr := meter.Float64Gauge(
			fmt.Sprintf("%s_compressed_size", serviceName),
			metric.WithDescription("size of compressed message"),
			metric.WithUnit("kB"))
		if mErr != nil {
			err = fmt.Errorf("failed to create compressed size metric: %w", err)
			return
		}

		// Create the retry connection count counter
		retryConnectionCount, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_retry_connection_count", serviceName),
			metric.WithDescription("number of retry connections"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create retry connection count metric: %w", err)
			return
		}

		// Create the missing required payload entities counter
		missingRequiredPayloadEntities, mErr := meter.Int64Counter(
			fmt.Sprintf("%s_missing_required_payload_entities", serviceName),
			metric.WithDescription("number of nodes that are missing required payload entities"),
		)
		if mErr != nil {
			err = fmt.Errorf("failed to create missing required payload entities metric: %w", err)
			return
		}

		singleton = &Monitoring{
			HostConnectionGauge:            hostConnectionGauge,
			GroupConnectionGauge:           groupConnectionGauge,
			ConnectionGauge:                connectionGauge,
			DisconnectionErrorCount:        disconnectionErrorCount,
			ReadMessageCount:               readMessageCount,
			ReadMessageErrorCount:          readMessageErrorCount,
			ReadMessagePanicCount:          readMessagePanicCount,
			PingCount:                      pingCount,
			PongCount:                      pongCount,
			UncompressedSize:               uncompressedSize,
			CompressedSize:                 compressedSize,
			RetryConnectionCount:           retryConnectionCount,
			MissingRequiredPayloadEntities: missingRequiredPayloadEntities,

			shutdown: shutdown,
			logger:   opts.Logger,
		}
	})

	return singleton, err
}

func (m *Monitoring) Shutdown(ctx context.Context) {
	timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	m.shutdown(timeoutCtx, m.logger)
}

func initOtelProvider(config config.OpenTelemetry) (
	func(ctx context.Context, logger *zap.Logger), *sdkmetric.MeterProvider, error,
) {
	// Create and set the global OpenTelemetry meter provider
	ctx := context.Background()
	endpoint := fmt.Sprintf("%s:%d", config.Host, config.Port)
	serviceName := strings.TrimSpace(strings.ToLower(config.ServiceName))
	metricExporter, err := otlpmetricgrpc.New(ctx,
		otlpmetricgrpc.WithEndpoint(endpoint),
		otlpmetricgrpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create open telemetry metric exporter: %w", err)
	}
	res, err := resource.New(ctx,
		resource.WithFromEnv(),
		resource.WithProcess(),
		resource.WithTelemetrySDK(),
		resource.WithHost(),
		resource.WithAttributes(
			semconv.ServiceNameKey.String(serviceName),
		),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create open telemetry resource: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithResource(res),
		sdkmetric.WithReader(
			sdkmetric.NewPeriodicReader(
				metricExporter,
				sdkmetric.WithInterval(config.MetricInterval),
			),
		),
	)
	otel.SetMeterProvider(mp)

	// Create and set the global OpenTelemetry tracer provider
	traceExporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure())
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create trace exporter: %w", err)
	}
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter),
		sdktrace.WithResource(res),
	)
	otel.SetTracerProvider(tp)

	// Create a shutdown function to ensure all traces and meters are properly
	// flushed
	return func(ctx context.Context, logger *zap.Logger) {
		timeoutCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		defer cancel()
		if err := tp.Shutdown(timeoutCtx); err != nil {
			logger.Warn("failed to shutdown trace provider", zap.Error(err))
		}
		if err := mp.Shutdown(timeoutCtx); err != nil {
			logger.Warn("failed to shutdown meter provider", zap.Error(err))
		}
	}, mp, nil
}
