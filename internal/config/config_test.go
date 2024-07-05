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
package config_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/mikefero/kheper/internal/config"
	"github.com/spf13/viper"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConfig(t *testing.T) {

	t.Run("verify defaults are set when overrides are not set", func(t *testing.T) {
		actual, err := config.NewConfig()
		require.NoError(t, err)

		expected := &config.Config{
			Server: config.Server{
				Port: 5000,
				Timeouts: config.Timeouts{
					Read:       15 * time.Second,
					ReadHeader: 15 * time.Second,
					Write:      15 * time.Second,
				},
			},
			Defaults: config.Defaults{
				HandshakeTimeout:     15 * time.Second,
				NodeCreationDelay:    20 * time.Millisecond,
				PingInterval:         15 * time.Second,
				PingJitter:           5 * time.Second,
				ReconnectionInterval: 10 * time.Second,
				ReconnectionJitter:   5 * time.Second,
			},
			Nodes: []config.Node{
				{
					Connection: config.Connection{
						Protocol: "standard",
					},
					Instances: 1,
					Hostname:  "sequential",
					ID:        "sequential",
					Versions:  []string{"3.7.0.0"},
				},
			},
		}
		require.Equal(t, expected, actual)
	})

	t.Run("verify full configuration when using environment variables and defaults", func(t *testing.T) {
		t.Setenv("KHEPER_SERVER_PORT", "4747")
		t.Setenv("KHEPER_SERVER_TIMEOUTS_READ_HEADER", "1s")
		t.Setenv("KHEPER_SERVER_TIMEOUTS_WRITE", "10s")
		t.Setenv("KHEPER_NODES_CONNECTION_HOST", "localhost")
		t.Setenv("KHEPER_NODES_CONNECTION_PORT", "3737")
		t.Setenv("KHEPER_NODES_CONNECTION_CERTIFICATE", "certificate")
		t.Setenv("KHEPER_NODES_CONNECTION_KEY", "key")
		actual, err := config.NewConfig()
		require.NoError(t, err)

		expected := &config.Config{
			Server: config.Server{
				Port: 4747,
				Timeouts: config.Timeouts{
					Read:       15 * time.Second,
					ReadHeader: 1 * time.Second,
					Write:      10 * time.Second,
				},
			},
			Defaults: config.Defaults{
				HandshakeTimeout:     15 * time.Second,
				NodeCreationDelay:    20 * time.Millisecond,
				PingInterval:         15 * time.Second,
				PingJitter:           5 * time.Second,
				ReconnectionInterval: 10 * time.Second,
				ReconnectionJitter:   5 * time.Second,
			},
			Nodes: []config.Node{
				{
					Connection: config.Connection{
						Host:        "localhost",
						Port:        3737,
						Protocol:    "standard",
						Certificate: "certificate",
						Key:         "key",
					},
					Instances: 1,
					Hostname:  "sequential",
					ID:        "sequential",
					Versions:  []string{"3.7.0.0"},
				},
			},
		}
		require.Equal(t, expected, actual)
	})

	t.Run("verify full configuration when using file and defaults", func(t *testing.T) {
		dir := t.TempDir()
		file, err := os.Create(filepath.Join(dir, "kheper.yaml"))
		if err != nil {
			t.Fatalf("unable to create config file: %v", err)
		}
		defer file.Close()
		_, err = file.Write([]byte(`server:
  port: 4747
  timeouts:
    write: 10s
nodes:
  connection:
    host: localhost
    port: 3737
    certificate: certificate
    key: key`))
		if err != nil {
			t.Fatalf("unable to write config file: %v", err)
		}
		viper.AddConfigPath(dir)
		defer viper.Reset()
		actual, err := config.NewConfig()
		require.NoError(t, err)

		expected := &config.Config{
			Server: config.Server{
				Port: 4747,
				Timeouts: config.Timeouts{
					Read:       15 * time.Second,
					ReadHeader: 15 * time.Second,
					Write:      10 * time.Second,
				},
			},
			Defaults: config.Defaults{
				HandshakeTimeout:     15 * time.Second,
				NodeCreationDelay:    20 * time.Millisecond,
				PingInterval:         15 * time.Second,
				PingJitter:           5 * time.Second,
				ReconnectionInterval: 10 * time.Second,
				ReconnectionJitter:   5 * time.Second,
			},
			Nodes: []config.Node{
				{
					Connection: config.Connection{
						Host:        "localhost",
						Port:        3737,
						Protocol:    "standard",
						Certificate: "certificate",
						Key:         "key",
					},
					Instances: 1,
					Hostname:  "sequential",
					ID:        "sequential",
					Versions:  []string{"3.7.0.0"},
				},
			},
		}
		require.Equal(t, expected, actual)
	})

	t.Run("verify precedence of full configuration when using file, environment variables, and defaults", func(t *testing.T) {
		t.Setenv("KHEPER_NODES_CONNECTION_HOST", "precedence.local")
		t.Setenv("KHEPER_NODES_CONNECTION_PORT", "4747")
		dir := t.TempDir()
		file, err := os.Create(filepath.Join(dir, "kheper.yaml"))
		if err != nil {
			t.Fatalf("unable to create config file: %v", err)
		}
		defer file.Close()
		_, err = file.Write([]byte(`server:
  port: 4747
  timeouts:
    read: 10s
    read_header: 10s
    write: 10s
nodes:
  connection:
    host: localhost
    port: 3737
    certificate: certificate
    key: key`))
		if err != nil {
			t.Fatalf("unable to write config file: %v", err)
		}
		viper.AddConfigPath(dir)
		defer viper.Reset()
		actual, err := config.NewConfig()
		require.NoError(t, err)

		expected := &config.Config{
			Server: config.Server{
				Port: 4747,
				Timeouts: config.Timeouts{
					Read:       10 * time.Second,
					ReadHeader: 10 * time.Second,
					Write:      10 * time.Second,
				},
			},
			Defaults: config.Defaults{
				HandshakeTimeout:     15 * time.Second,
				NodeCreationDelay:    20 * time.Millisecond,
				PingInterval:         15 * time.Second,
				PingJitter:           5 * time.Second,
				ReconnectionInterval: 10 * time.Second,
				ReconnectionJitter:   5 * time.Second,
			},
			Nodes: []config.Node{
				{
					Connection: config.Connection{
						Host:        "precedence.local",
						Port:        4747,
						Protocol:    "standard",
						Certificate: "certificate",
						Key:         "key",
					},
					Instances: 1,
					Hostname:  "sequential",
					ID:        "sequential",
					Versions:  []string{"3.7.0.0"},
				},
			},
		}
		require.Equal(t, expected, actual)
	})

	t.Run("verify defaults are overridden when environment variables are set", func(t *testing.T) {
		t.Setenv("KHEPER_SERVER_PORT", "4747")
		t.Setenv("KHEPER_SERVER_TIMEOUTS_READ", "10s")
		t.Setenv("KHEPER_SERVER_TIMEOUTS_READ_HEADER", "10s")
		t.Setenv("KHEPER_SERVER_TIMEOUTS_WRITE", "10s")
		t.Setenv("KHEPER_DEFAULTS_HANDSHAKE_TIMEOUT", "1s")
		t.Setenv("KHEPER_DEFAULTS_NODE_CREATION_DELAY", "2ms")
		t.Setenv("KHEPER_DEFAULTS_PING_INTERVAL", "3s")
		t.Setenv("KHEPER_DEFAULTS_PING_JITTER", "4s")
		t.Setenv("KHEPER_DEFAULTS_RECONNECTION_INTERVAL", "1s")
		t.Setenv("KHEPER_DEFAULTS_RECONNECTION_JITTER", "2s")
		t.Setenv("KHEPER_NODES_INSTANCES", "5")
		t.Setenv("KHEPER_NODES_HOSTNAME", "kheper.local")
		t.Setenv("KHEPER_NODES_ID", "unique")
		t.Setenv("KHEPER_NODES_CONNECTION_PROTOCOL", "jsonrpc")
		t.Setenv("KHEPER_NODES_VERSIONS", "3.6.0.0,3.5.0.0")
		actual, err := config.NewConfig()
		if err != nil {
			t.Fatalf("unable to create config: %v", err)
		}

		expected := &config.Config{
			Server: config.Server{
				Port: 4747,
				Timeouts: config.Timeouts{
					Read:       10 * time.Second,
					ReadHeader: 10 * time.Second,
					Write:      10 * time.Second,
				},
			},
			Defaults: config.Defaults{
				HandshakeTimeout:     time.Second,
				NodeCreationDelay:    2 * time.Millisecond,
				PingInterval:         3 * time.Second,
				PingJitter:           4 * time.Second,
				ReconnectionInterval: 1 * time.Second,
				ReconnectionJitter:   2 * time.Second,
			},
			Nodes: []config.Node{
				{
					Connection: config.Connection{
						Protocol: "jsonrpc",
					},
					Instances: 5,
					Hostname:  "kheper.local",
					ID:        "unique",
					Versions:  []string{"3.6.0.0", "3.5.0.0"},
				},
			},
		}
		require.Equal(t, expected, actual)
	})

	t.Run("verify defaults are overridden when configuration file is set", func(t *testing.T) {
		dir := t.TempDir()
		expected := &config.Config{
			Server: config.Server{
				Port: 4747,
				Timeouts: config.Timeouts{
					Read:       10 * time.Second,
					ReadHeader: 10 * time.Second,
					Write:      10 * time.Second,
				},
			},
			Defaults: config.Defaults{
				HandshakeTimeout:     1 * time.Second,
				NodeCreationDelay:    2 * time.Millisecond,
				PingInterval:         3 * time.Second,
				PingJitter:           4 * time.Second,
				ReconnectionInterval: 1 * time.Second,
				ReconnectionJitter:   2 * time.Second,
			},
			Nodes: []config.Node{
				{
					Connection: config.Connection{
						Protocol: "jsonrpc",
					},
					Instances: 5,
					Hostname:  "kheper.local",
					ID:        "unique",
					Versions:  []string{"3.6.0.0", "3.5.0.0"},
				},
			},
		}
		data, err := yaml.Marshal(expected)
		if err != nil {
			t.Fatalf("unable to marshal config: %v", err)
		}
		file, err := os.Create(filepath.Join(dir, "kheper.yaml"))
		if err != nil {
			t.Fatalf("unable to create config file: %v", err)
		}
		defer file.Close()
		_, err = file.Write(data)
		if err != nil {
			t.Fatalf("unable to write config file: %v", err)
		}

		viper.AddConfigPath(dir)
		defer viper.Reset()
		actual, err := config.NewConfig()
		require.NoError(t, err)
		require.Equal(t, expected, actual)
	})

	t.Run("verify yaml marshal failure using invalid configuration", func(t *testing.T) {
		dir := t.TempDir()
		file, err := os.Create(filepath.Join(dir, "kheper.yaml"))
		if err != nil {
			t.Fatalf("unable to create config file: %v", err)
		}
		defer file.Close()
		_, err = file.Write([]byte(`defaults:
  handshake_timeout: invalid`))
		if err != nil {
			t.Fatalf("unable to write config file: %v", err)
		}

		viper.AddConfigPath(dir)
		defer viper.Reset()
		cfg, err := config.NewConfig()
		require.ErrorContains(t, err, "unable to unmarshal config")
		require.Nil(t, cfg)
	})
}
