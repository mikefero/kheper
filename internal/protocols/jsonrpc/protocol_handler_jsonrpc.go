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
package jsonrpc

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/Kong/go-openrpc/websocket"

	gorillaWebsocket "github.com/gorilla/websocket"
	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/store"
	"github.com/mikefero/kheper/node"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

const (
	CapabilitiesHeaderKey = "X-Kong-RPC-Capabilities"
)

type HandlerBuilder struct {
	Globals *config.GlobalsNode
	Node    *config.Node
}

func (b *HandlerBuilder) Build(opts node.ProtocolHandlerBuildOpts) (node.ProtocolHandler, error) {

	handler := &protocolHandlerJSONRPC{
		db:             opts.Db,
		logger:         opts.Logger,
		nodeInfo:       opts.NodeInfo,
		numConnections: b.Node.NumConnections,
		pingInterval:   b.Globals.PingInterval,
		pingJitter:     b.Globals.PingJitter,
		attributes:     opts.Attributes,
		metrics:        opts.Metrics,
		serverURL: url.URL{
			Scheme: "wss",
			Host:   fmt.Sprintf("%s:%d", opts.ConnectionOpts.Host, opts.ConnectionOpts.Port),
			Path:   "/v2/outlet",
			RawQuery: url.Values{
				"node_id":       []string{opts.NodeInfo.ID.String()},
				"node_hostname": []string{opts.ConnectionOpts.Host},
				"node_version":  []string{opts.NodeInfo.Version.String()},
			}.Encode(),
		},
		dialer: gorillaWebsocket.Dialer{
			HandshakeTimeout: b.Globals.HandshakeTimeout,
			TLSClientConfig:  opts.ConnectionOpts.TLSConfig,
			Subprotocols:     []string{"kong.rpc.v1"},
		},
		capabilityNames: b.Node.Capabilities,
	}

	return handler, nil
}

type protocolHandlerJSONRPC struct {
	db             *database.Database
	logger         *zap.Logger
	serverURL      url.URL
	nodeInfo       node.Info
	numConnections int
	pingInterval   time.Duration
	pingJitter     time.Duration

	attributes []attribute.KeyValue
	metrics    *monitoring.Monitoring

	dialer          gorillaWebsocket.Dialer
	connections     []*runtime.Conn
	capabilityNames []string
}

func (s *protocolHandlerJSONRPC) IsConnected() bool {
	return len(s.connections) > 0
}

func (s *protocolHandlerJSONRPC) Run(ctx context.Context) error {

	capabilitiesHeader, err := json.Marshal(s.capabilityNames)
	if err != nil {
		return err
	}

	reqHeader := http.Header{
		CapabilitiesHeaderKey: []string{string(capabilitiesHeader)},
	}

	snappy := websocket.NewSnappyCodec()
	s.connections = make([]*runtime.Conn, s.numConnections)

	for i := range s.numConnections {
		wsConn, resp, err := s.dialer.Dial(s.serverURL.String(), reqHeader)
		if err != nil {
			return fmt.Errorf("failed to dial connection #%d: %w", i, err)
		}
		_ = resp

		s.connections[i] = runtime.NewConnection(websocket.NewWebsocketTransport(wsConn, snappy))
		s.connections[i].SetUserData(store.NewMethodStore(s.db, s.nodeInfo.ID))
		err = s.registerCapabilities(s.connections[i], resp.Header.Get(CapabilitiesHeaderKey))
		if err != nil {
			return err
		}
	}
	return nil
}

func (s *protocolHandlerJSONRPC) registerCapabilities(conn *runtime.Conn, capabilitiesHeader string) error {
	capabilityNames := []string{}
	err := json.Unmarshal([]byte(capabilitiesHeader), &capabilityNames)
	if err != nil {
		return err
	}

	s.logger.Info("negotiated capabilities", zap.Strings("capabilities", capabilityNames))

	for _, k := range capabilityNames {
		if err = capabilities.RegisterByName(conn, k); err != nil {
			return err
		}
	}

	return nil
}

func (s *protocolHandlerJSONRPC) Close() error {
	for _, conn := range s.connections {
		conn.Close()
	}
	s.connections = nil
	return nil
}
