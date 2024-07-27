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
	defaultHandshakeTimeout        = 15 * time.Second
	defaultNodeCreationDelay       = 20 * time.Millisecond
	defaultPingInterval            = 15 * time.Second
	defaultPingJitter              = 5 * time.Second
	defaultReconnectionInterval    = 10 * time.Second
	defaultReconnectionJitter      = 5 * time.Second
	defaultServerPort              = 5000
	defaultServerReadTimeout       = 15 * time.Second
	defaultServerReadHeaderTimeout = 15 * time.Second
	defaultServerWriteTimeout      = 15 * time.Second
	defaultNodeProtocol            = "standard"
	defaultNodeHostname            = "sequential"
	defaultNodeID                  = "sequential"
	defaultNodeInstances           = 1
)

var defaultNodeVersions = []string{"3.7.0.0"}

// Config is the configuration for the connection and mock nodes to instantiate
// and run.
type Config struct {
	// Defaults are the default values for the nodes.
	Defaults Defaults `yaml:"defaults" mapstructure:"defaults"`
	// Nodes are the nodes to instantiate and run.
	Nodes []Node `yaml:"nodes" mapstructure:"nodes"`
	// Server is the configuration for the API server to run.
	Server Server `yaml:"server" mapstructure:"server"`
}

// Defaults are the default values for the nodes.
type Defaults struct {
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

// Node is the configuration for the connection and mock nodes to instantiate
// and run.
type Node struct {
	// Connection is the configuration for the connection to the control plane.
	Connection Connection `yaml:"connection" mapstructure:"connection"`
	// Instances is the number of nodes to create.
	Instances int `yaml:"instances" mapstructure:"instances"`
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
	// Versions is the Kong Gateway semantic versions of the node. This version
	// can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or
	// 1.2.3.4). Each version in the slice will be "round-robin" across the
	// nodes based on the number of instances.
	Versions []string `yaml:"versions" mapstructure:"versions"`
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

// Server is the configuration for the API server to run.
type Server struct {
	// Port is the port to run the API server on.
	Port int `yaml:"port" mapstructure:"port"`
	// Timeouts are the timeouts for the API server.
	Timeouts Timeouts `yaml:"timeouts" mapstructure:"timeouts"`
}

// Timeouts are the timeouts for the API server.
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
	// Connection defaults
	viper.SetDefault("defaults.handshake_timeout", defaultHandshakeTimeout)
	viper.SetDefault("defaults.node_creation_delay", defaultNodeCreationDelay)
	viper.SetDefault("defaults.ping_interval", defaultPingInterval)
	viper.SetDefault("defaults.ping_jitter", defaultPingJitter)
	viper.SetDefault("defaults.reconnection_interval", defaultReconnectionInterval)
	viper.SetDefault("defaults.reconnection_jitter", defaultReconnectionJitter)

	// Node defaults
	viper.SetDefault("nodes.hostname", defaultNodeHostname)
	viper.SetDefault("nodes.id", defaultNodeID)
	viper.SetDefault("nodes.instances", defaultNodeInstances)
	viper.SetDefault("nodes.versions", defaultNodeVersions)

	// Node connection defaults
	viper.SetDefault("nodes.connection.protocol", defaultNodeProtocol)

	// Server defaults
	viper.SetDefault("server.port", defaultServerPort)
	viper.SetDefault("server.timeouts.read", defaultServerReadTimeout)
	viper.SetDefault("server.timeouts.read_header", defaultServerReadHeaderTimeout)
	viper.SetDefault("server.timeouts.write", defaultServerWriteTimeout)

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
