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
package node

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kong/semver/v4"
	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/mikefero/kheper/internal/server"
	"github.com/mikefero/kheper/internal/utils"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

var (
	// ErrNodeConnected is returned when the node is already started and connected.
	ErrNodeConnected = errors.New("node is already started and connected")

	apiServer             *http.Server
	once                  sync.Once
	monitoringEnabledOnce sync.Once
)

// Node is a mock Kong Gateway data plane node.
type Node struct {
	handler ProtocolHandler
	logger  *zap.Logger
}

// Opts are the options used to create a new node.
type Opts struct {
	// Host is the RFC 1123 IP address or hostname of the control plane to connect
	// to. Host must be a valid RFC 1123 hostname.
	Host string
	// Port is the port of the control plane to connect to. Port must be in the
	// range 1-65535.
	Port int
	// HandlerBuilder is the injected builder for the protocol handler.
	HandlerBuilder ProtocolHandlerBuilder
	// Certificate is the TLS certificate to use when connecting to the control
	// plane.
	Certificate tls.Certificate
	// CipherSuite is the TLS cipher suite to use when connecting to the control
	// plane.
	CipherSuite uint16
	// TLSVersion is the TLS version to use when connecting to the control plane.
	TLSVersion uint16

	// ID is the unique ID of the node.
	ID uuid.UUID
	// Hostname is the RFC 1123 hostname of the node.
	Hostname string
	// RequiredPayloadEntities is the list of entities that must be present in
	// the configuration payload sent from the control plane.
	RequiredPayloadEntities []string
	// Version is the Kong Gateway semantic version of the node. This version
	// can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or
	// 1.2.3.4).
	Version semver.Version

	// Group is the name of the group to which the node instance belongs.
	Group *string
	// APIConfiguration is the configuration for the API server to run. If
	// nil, the API server will not be started.
	APIConfiguration *config.API
	// OpenTelemetry is the configuration for the observability server to run.
	OpenTelemetry config.OpenTelemetry

	// Logger is the logger to use for logging.
	Logger *zap.Logger
}

// Info is a list of information about the node.
type Info struct {
	// ID is the unique ID of the node.
	ID uuid.UUID
	// Host is the RFC 1123 IP address or hostname of the control plane connected
	// to.
	Host string
	// Hostname is the RFC 1123 hostname of the node.
	Hostname string
	// RequiredPayloadEntities is the list of entities that must be present in
	// the configuration payload sent from the control plane.
	RequiredPayloadEntities []string
	// Version is the Kong Gateway semantic version of the node. This version
	// can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or
	// 1.2.3.4).
	Version semver.Version

	// Group is the name of the group to which the node instance belongs.
	Group *string
}

// NewNode creates a new node.
func NewNode(opts Opts) (*Node, error) {
	// Validate the options
	if err := utils.ValidateHostname(opts.Host); err != nil {
		return nil, fmt.Errorf("invalid host: %w", err)
	}
	if err := utils.ValidatePort(opts.Port); err != nil {
		return nil, fmt.Errorf("invalid port: %w", err)
	}
	if opts.HandlerBuilder == nil {
		return nil, errors.New("missing handler builder")
	}
	if opts.ID == uuid.Nil {
		return nil, errors.New("node ID must be set")
	}
	if err := utils.ValidateHostname(opts.Hostname); err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}
	if opts.Logger == nil {
		return nil, errors.New("logger must be set")
	}

	// Create the database for the node(s)
	db, err := database.NewDatabase()
	if err != nil {
		return nil, fmt.Errorf("error creating database: %w", err)
	}

	// Create the monitoring instance
	metrics, err := monitoring.NewMonitoring(monitoring.Opts{
		OpenTelemetry: opts.OpenTelemetry,
		Logger:        opts.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating monitoring: %w", err)
	}
	monitoringEnabledOnce.Do(func() {
		if opts.OpenTelemetry.Enabled {
			opts.Logger.Info("monitoring enabled",
				zap.String("host", opts.OpenTelemetry.Host),
				zap.Int("port", opts.OpenTelemetry.Port),
				zap.String("service-name", opts.OpenTelemetry.ServiceName),
				zap.Duration("metric-interval", opts.OpenTelemetry.MetricInterval),
				zap.Duration("shutdown-interval", opts.OpenTelemetry.ShutdownInterval),
			)
		}
	})

	// Create the API server for the node(s)
	if opts.APIConfiguration != nil && opts.APIConfiguration.Enabled {
		apiServer, err = server.NewServer(server.Opts{
			Database:             db,
			Port:                 opts.APIConfiguration.Port,
			ReadTimeout:          opts.APIConfiguration.Timeouts.Read,
			ReadHeaderTimeout:    opts.APIConfiguration.Timeouts.ReadHeader,
			WriteTimeout:         opts.APIConfiguration.Timeouts.Write,
			OpenTelemetryEnabled: opts.OpenTelemetry.Enabled,
			Logger:               opts.Logger,
		})
		if err != nil {
			return nil, fmt.Errorf("error creating API server: %w", err)
		}
	}

	// Initialize the node logger with the node ID and host
	var nodeLogger *zap.Logger
	if opts.Group != nil {
		nodeLogger = opts.Logger.With(
			zap.Any("group", opts.Group),
			zap.String("host", opts.Host),
			zap.String("hostname", opts.Hostname),
			zap.String("id", opts.ID.String()),
			zap.Any("version", opts.Version),
		)
	} else {
		nodeLogger = opts.Logger.With(
			zap.String("host", opts.Host),
			zap.String("hostname", opts.Hostname),
			zap.String("id", opts.ID.String()),
			zap.Any("version", opts.Version),
		)
	}

	// Initialize the node information
	info := Info{
		Group:                   opts.Group,
		Host:                    opts.Host,
		Hostname:                opts.Hostname,
		ID:                      opts.ID,
		RequiredPayloadEntities: opts.RequiredPayloadEntities,
		Version:                 opts.Version,
	}

	// Initialize the trace attributes
	traceAttributes := []attribute.KeyValue{
		attribute.String("host", opts.Host),
		attribute.String("hostname", opts.Hostname),
		attribute.String("node-id", opts.ID.String()),
		attribute.String("group", opts.OpenTelemetry.ServiceName),
		attribute.String("version", opts.Version.String()),
	}

	// Create the WebSocket client and associate with the node
	tlsConfig := &tls.Config{
		InsecureSkipVerify: true, //nolint: gosec
		Certificates:       []tls.Certificate{opts.Certificate},
	}
	if opts.CipherSuite != 0 {
		tlsConfig.CipherSuites = []uint16{opts.CipherSuite}
	}
	if opts.TLSVersion != 0 {
		tlsConfig.MinVersion = opts.TLSVersion
		tlsConfig.MaxVersion = opts.TLSVersion
	}

	handler, err := opts.HandlerBuilder.Build(ProtocolHandlerBuildOpts{
		Db:       db,
		Logger:   nodeLogger,
		NodeInfo: info,
		ConnectionOpts: ConnectionOpts{
			Host:      opts.Host,
			Port:      opts.Port,
			TLSConfig: tlsConfig,
		},
		Metrics:    metrics,
		Attributes: traceAttributes,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to build protocol handler: %w", err)
	}

	return &Node{
		handler: handler,
		logger:  nodeLogger,
	}, nil
}

// Run runs then node with the given context.
func (n *Node) Run(ctx context.Context) error {
	// Verify that the node is not already connected
	if n.handler.IsConnected() {
		return ErrNodeConnected
	}
	defer n.handler.Close()

	// Start the admin API server if set
	if apiServer != nil {
		once.Do(func() {
			go func() {
				serverCloseCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				defer cancel()

				n.logger.Info("starting API server")
				if err := apiServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
					n.logger.Error("error occurred while starting API server", zap.Error(err))
					return
				}
				if err := apiServer.Shutdown(serverCloseCtx); err != nil {
					n.logger.Error("error occurred while shutting down API server", zap.Error(err))
				}
			}()
		})
	}

	// Start the node
	if err := n.handler.Run(ctx); err != nil {
		return fmt.Errorf("error occurred while running client: %w", err)
	}
	n.logger.Info("starting node")
	return nil
}
