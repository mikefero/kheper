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
package config

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/viper"
)

const (
	defaultAPIEnabled                    = false
	defaultAPIPort                       = 5000
	defaultAPIReadTimeout                = 15 * time.Second
	defaultAPIReadHeaderTimeout          = 15 * time.Second
	defaultAPIWriteTimeout               = 15 * time.Second
	defaultOpenTelemetryEnabled          = false
	defaultOpenTelemetryHost             = "localhost"
	defaultOpenTelemetryPort             = 4317
	defaultOpenTelemetryServiceName      = "kheper"
	defaultOpenTelemetryMetricInterval   = 2 * time.Second
	defaultOpenTelemetryShutdownInterval = 10 * time.Second
	defaultHandshakeTimeout              = 15 * time.Second
	defaultNodeCreationDelay             = 20 * time.Millisecond
	defaultPingInterval                  = 15 * time.Second
	defaultPingJitter                    = 5 * time.Second
	defaultReconnectionInterval          = 10 * time.Second
	defaultReconnectionJitter            = 5 * time.Second
	defaultNodeProtocol                  = "standard"
	defaultNodeHostname                  = "sequential"
	defaultNodeID                        = "sequential"
	defaultNodeInstances                 = 1
	defaultNodeConnections               = 1
)

var defaultNodeVersions = []string{"3.7.1"}

// Config is the configuration for the connection and mock nodes to instantiate
// and run.
type Config struct {
	// API is the configuration for the admin API server to run.
	API API `yaml:"api" mapstructure:"api"`
	// Globals are the global values for various features of Kheper.
	Globals Globals `yaml:"globals" mapstructure:"globals"`
	// Nodes are the nodes to instantiate and run.
	Nodes []Node `yaml:"nodes" mapstructure:"nodes"`
	// OpenTelemetry is the configuration values for the OpenTelemetry collector.
	OpenTelemetry OpenTelemetry `yaml:"open_telemetry" mapstructure:"open_telemetry"`
}

// API is the configuration for the admin API server to run.
type API struct {
	// Enabled is whether the admin API server should be enabled.
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// Port is the port to run the admin API server on.
	Port int `yaml:"port" mapstructure:"port"`
	// Timeouts are the timeouts for the admin API server.
	Timeouts Timeouts `yaml:"timeouts" mapstructure:"timeouts"`
}

// Global are the global values for various features of Kheper.
type Globals struct {
	// Node is the global configuration values for the nodes.
	Node GlobalsNode `yaml:"node" mapstructure:"node"`
}

// GlobalsNode are the global configuration values for the nodes.
type GlobalsNode struct {
	// HandshakeTimeout is the amount of time allowed to complete the WebSocket
	// handshake.
	HandshakeTimeout time.Duration `yaml:"handshake_timeout" mapstructure:"handshake_timeout"`
	// NodeCreationDelay is the amount of time to wait before creating the next
	// node.
	NodeCreationDelay time.Duration `yaml:"node_creation_delay" mapstructure:"node_creation_delay"`
	// PingInterval is the interval at which the node should ping the control
	// plane.
	PingInterval time.Duration `yaml:"ping_interval" mapstructure:"ping_interval"`
	// PingJitter is the jitter to apply to the ping interval.
	PingJitter time.Duration `yaml:"ping_jitter" mapstructure:"ping_jitter"`
	// ReconnectionInterval is the interval at which the node should attempt to
	// reconnect to the control plane.
	ReconnectionInterval time.Duration `yaml:"reconnection_interval" mapstructure:"reconnection_interval"`
	// ReconnectionJitter is the jitter to apply to the reconnection interval.
	ReconnectionJitter time.Duration `yaml:"reconnection_jitter" mapstructure:"reconnection_jitter"`
}

// OpenTelemetry is the configuration values for the OpenTelemetry collector.
type OpenTelemetry struct {
	// Enabled is whether the OpenTelemetry collector should be enabled.
	Enabled bool `yaml:"enabled" mapstructure:"enabled"`
	// Host is the host of the OpenTelemetry collector.
	Host string `yaml:"host" mapstructure:"host"`
	// Port is the port of the OpenTelemetry collector.
	Port int `yaml:"port" mapstructure:"port"`
	// ServiceName is the service name for the traces and metrics sent to the
	// OpenTelemetry collector.
	ServiceName string `yaml:"service_name" mapstructure:"service_name"`
	// MetricInterval is the interval at which the OpenTelemetry collector should
	// collect metrics.
	MetricInterval time.Duration `yaml:"metric_interval" mapstructure:"metric_interval"`
	// ShutdownInterval is the interval at which the OpenTelemetry collector should
	// shutdown.
	ShutdownInterval time.Duration `yaml:"shutdown_interval" mapstructure:"shutdown_interval"`
}

// Node is the configuration for the connection and mock nodes to instantiate
// and run.
type Node struct {
	// Connection is the configuration for the connection to the control plane.
	Connection Connection `yaml:"connection" mapstructure:"connection"`
	// Instances is the number of nodes to create.
	Instances int `yaml:"instances" mapstructure:"instances"`
	// NumConnections is the number of connections per node
	NumConnections int `yaml:"num_connections" mapstructure:"num_connections"`
	// Group is the name of the group to which the node instance belongs.
	Group *string `yaml:"group" mapstructure:"group"`
	// Hostname is the RFC 1123 hostname of the node. If 'sequential' is specified
	// a sequential hostname will be generated; otherwise, the hostname will be
	// used as-is.
	Hostname string `yaml:"hostname" mapstructure:"hostname"`
	// ID is the unique ID of the node. If 'sequential' is specified a sequential
	// ID will be generated, if 'unique' is specified a unique ID will be
	// generated; otherwise, the ID will be used as-is.
	ID string `yaml:"id" mapstructure:"id"`
	// RequiredPayloadEntities is the list of entities that must be present in
	// the configuration payload sent from the control plane.
	RequiredPayloadEntities []string `yaml:"required_payload_entities" mapstructure:"required_payload_entities"`
	// Versions is the Kong Gateway semantic versions of the node. This version
	// can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or
	// 1.2.3.4). Each version in the slice will be "round-robin" across the
	// nodes based on the number of instances.
	Versions []string `yaml:"versions" mapstructure:"versions"`
	// Capabilities is the set of RPC capabilities the node will ask to the DP.
	// Each one should be the full name, including version.
	// It's valid to include more than one version of the same capability.
	Capabilities []string `yaml:"capabilities" mapstructure:"capabilities"`
}

// Connection is the configuration for the connection to the control plane.
type Connection struct {
	// Host is the RFC 1123 IP address or hostname of the control plane to connect
	// to. Host must be a valid RFC 1123 hostname.
	Host string `yaml:"host" mapstructure:"host"`
	// Port is the port of the control plane to connect to. Port must be in the
	// range 1-65535.
	Port int `yaml:"port" mapstructure:"port"`
	// Protocol is the protocol to use to communicate with the control plane.
	Protocol string `yaml:"protocol" mapstructure:"protocol"`
	// CipherSuites is the TLS cipher suite to use when connecting to the control
	// plane. Each cipher suite in the slice will be "round-robin" across the
	// nodes based on the number of instances.
	CipherSuites []string `yaml:"cipher_suites" mapstructure:"cipher_suites"`
	// TLSVersion is the TLS cipher version to use when connecting to the control
	// plane.
	TLSVersion string `yaml:"tls_version" mapstructure:"tls_version"`
	// Certificate is the TLS certificate to use when connecting to the control
	// plane.
	Certificate string `yaml:"certificate" mapstructure:"certificate"`
	// Key is the TLS key to use when connecting to the control plane.
	Key string `yaml:"key" mapstructure:"key"`
}

// Timeouts are the timeouts for the admin API server.
type Timeouts struct {
	// Read is the timeout for reading the request body.
	Read time.Duration `yaml:"read" mapstructure:"read"`
	// ReadHeader is the timeout for reading the headers.
	ReadHeader time.Duration `yaml:"read_header" mapstructure:"read_header"`
	// Write is the timeout for writing the response.
	Write time.Duration `yaml:"write" mapstructure:"write"`
}

// NewConfig creates a new configuration comprised of the configuration file,
// environment variables, and defaults.
func NewConfig() (*Config, error) {
	// API defaults
	viper.SetDefault("api.enabled", defaultAPIEnabled)
	viper.SetDefault("api.port", defaultAPIPort)
	viper.SetDefault("api.timeouts.read", defaultAPIReadTimeout)
	viper.SetDefault("api.timeouts.read_header", defaultAPIReadHeaderTimeout)
	viper.SetDefault("api.timeouts.write", defaultAPIWriteTimeout)

	// OpenTelemetry defaults
	viper.SetDefault("open_telemetry.enabled", defaultOpenTelemetryEnabled)
	viper.SetDefault("open_telemetry.host", defaultOpenTelemetryHost)
	viper.SetDefault("open_telemetry.port", defaultOpenTelemetryPort)
	viper.SetDefault("open_telemetry.service_name", defaultOpenTelemetryServiceName)
	viper.SetDefault("open_telemetry.metric_interval", defaultOpenTelemetryMetricInterval)
	viper.SetDefault("open_telemetry.shutdown_interval", defaultOpenTelemetryShutdownInterval)

	// Node connection defaults
	viper.SetDefault("globals.node.handshake_timeout", defaultHandshakeTimeout)
	viper.SetDefault("globals.node.node_creation_delay", defaultNodeCreationDelay)
	viper.SetDefault("globals.node.ping_interval", defaultPingInterval)
	viper.SetDefault("globals.node.ping_jitter", defaultPingJitter)
	viper.SetDefault("globals.node.reconnection_interval", defaultReconnectionInterval)
	viper.SetDefault("globals.node.reconnection_jitter", defaultReconnectionJitter)

	// Node defaults
	viper.SetDefault("nodes.hostname", defaultNodeHostname)
	viper.SetDefault("nodes.id", defaultNodeID)
	viper.SetDefault("nodes.instances", defaultNodeInstances)
	viper.SetDefault("nodes.versions", defaultNodeVersions)
	viper.SetDefault("nodes.num_connections", defaultNodeConnections)

	// Node connection defaults
	viper.SetDefault("nodes.connection.protocol", defaultNodeProtocol)

	// Kheper configuration setup for viper
	viper.SetConfigName("kheper")
	viper.SetConfigType("yaml")
	viper.AddConfigPath(".")
	viper.SetEnvKeyReplacer(strings.NewReplacer(".", "_"))

	// Bind environment variables to viper that do not have a corresponding
	// default value
	viper.SetEnvPrefix("kheper")
	if err := viper.BindEnv("nodes.group"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.group environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.required_payload_entities"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.required_payload_entities environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.connection.host"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.connection.host environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.connection.port"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.connection.port environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.connection.certificate"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.connection.certificate environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.connection.key"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.connection.key environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.connection.cipher_suites"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.connection.cipher_suites environment variable: %w", err)
	}
	if err := viper.BindEnv("nodes.connection.tls_version"); err != nil {
		return nil, fmt.Errorf("unable to bind nodes.connection.tls_version environment variable: %w", err)
	}

	// Enable automatic environment variable binding
	viper.AutomaticEnv()

	// Read in the configuration file and ignore not found errors as environment
	// variables will be used if the file is not found. If the required
	// configuration fields are not present then and error will be returned
	// further down the line.
	var config Config
	_ = viper.ReadInConfig()
	if err := viper.Unmarshal(&config); err != nil {
		return nil, fmt.Errorf("unable to unmarshal config: %w", err)
	}
	return &config, nil
}
