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
	"net/url"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/kong/semver/v4"
	"github.com/mikefero/ankh"
	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/server"
	"github.com/mikefero/kheper/internal/utils"
	"go.uber.org/zap"
)

var (
	// ErrNodeConnected is returned when the node is already started and connected.
	ErrNodeConnected = errors.New("node is already started and connected")

	apiServer *http.Server
	once      sync.Once
)

// Node is a mock Kong Gateway data plane node.
type Node struct {
	client    *ankh.WebSocketClient
	handler   protocolHandler
	logger    *zap.Logger
	serverURL url.URL
}

// Opts are the options used to create a new node.
type Opts struct {
	// Host is the RFC 1123 IP address or hostname of the control plane to connect
	// to. Host must be a valid RFC 1123 hostname.
	Host string
	// Port is the port of the control plane to connect to. Port must be in the
	// range 1-65535.
	Port int
	// Protocol is the protocol to use to communicate with the control plane.
	Protocol Protocol
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
	// Version is the Kong Gateway semantic version of the node. This version
	// can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or
	// 1.2.3.4).
	Version semver.Version
	// HandshakeTimeout is the amount of time allowed to complete the WebSocket
	// handshake.
	HandshakeTimeout time.Duration
	// PingInterval is the interval at which the node should ping the control
	// plane. This value must be > 0.
	PingInterval time.Duration
	// PingJitter is the jitter to apply to the ping interval.
	PingJitter time.Duration

	// Group is the name of the group to which the node instance belongs.
	Group *string
	// ServerConfiguration is the configuration for the API server to run. If
	// nil, the API server will not be started.
	ServerConfiguration *config.Server

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
	if opts.Protocol == JSONRPC {
		return nil, fmt.Errorf("%s is not supported", JSONRPC)
	}
	if opts.ID == uuid.Nil {
		return nil, errors.New("node ID must be set")
	}
	if err := utils.ValidateHostname(opts.Hostname); err != nil {
		return nil, fmt.Errorf("invalid hostname: %w", err)
	}
	if opts.PingInterval <= 0 {
		return nil, errors.New("ping interval must be > 0")
	}
	if opts.PingJitter <= 0 {
		return nil, errors.New("ping jitter must be > 0")
	}
	if opts.Logger == nil {
		return nil, errors.New("logger must be set")
	}

	// Create the database for the node(s)
	db, err := database.NewDatabase()
	if err != nil {
		return nil, fmt.Errorf("error creating database: %w", err)
	}

	// Create the API server for the node(s)
	if opts.ServerConfiguration != nil {
		apiServer, err = server.NewServer(server.Opts{
			Database:          db,
			Port:              opts.ServerConfiguration.Port,
			ReadTimeout:       opts.ServerConfiguration.Timeouts.Read,
			ReadHeaderTimeout: opts.ServerConfiguration.Timeouts.ReadHeader,
			WriteTimeout:      opts.ServerConfiguration.Timeouts.Write,
			Logger:            opts.Logger,
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
		Group:    opts.Group,
		Host:     opts.Host,
		Hostname: opts.Hostname,
		ID:       opts.ID,
		Version:  opts.Version,
	}

	// Create the appropriate protocol handler, path, and server URL
	var handler protocolHandler
	path := "/v1/outlet"
	serverURL := url.URL{
		Scheme: "wss",
		Host:   fmt.Sprintf("%s:%d", opts.Host, opts.Port),
	}
	if opts.Protocol == Standard {
		handler = &protocolHandlerStandard{
			db:           db,
			logger:       nodeLogger,
			nodeInfo:     info,
			pingInterval: opts.PingInterval,
			pingJitter:   opts.PingJitter,
		}
		serverURL.RawQuery = url.Values{
			"node_id":       []string{opts.ID.String()},
			"node_hostname": []string{opts.Hostname},
			"node_version":  []string{opts.Version.String()},
		}.Encode()
	} else if opts.Protocol == JSONRPC {
		handler = &protocolHandlerJSONRPC{
			db:           db,
			logger:       nodeLogger,
			nodeInfo:     info,
			pingInterval: opts.PingInterval,
			pingJitter:   opts.PingJitter,
		}
		path = "/v2/outlet"
		panic("JSON RPC is not supported")
	}
	serverURL.Path = path

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
	client, err := ankh.NewWebSocketClient(ankh.WebSocketClientOpts{
		Handler:          handler,
		HandShakeTimeout: opts.HandshakeTimeout,
		ServerURL:        serverURL,
		TLSConfig:        tlsConfig,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create WebSocket client: %w", err)
	}

	return &Node{
		client:    client,
		handler:   handler,
		logger:    nodeLogger,
		serverURL: serverURL,
	}, nil
}

// Run runs then node with the given context.
func (n *Node) Run(ctx context.Context) error {
	// Verify that the node is not already connected
	if n.client.IsConnected() {
		return ErrNodeConnected
	}
	defer n.handler.close()

	// Start the API server if set
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
	n.logger.Debug("starting node")
	if err := n.client.Run(ctx); err != nil {
		return fmt.Errorf("error occurred while running client: %w", err)
	}
	return nil
}
