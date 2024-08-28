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
	"sync"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/Kong/go-openrpc/websocket"

	gorillaWebsocket "github.com/gorilla/websocket"
	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/kong_sync/v2"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/store"
	"github.com/mikefero/kheper/internal/tick"
	"github.com/mikefero/kheper/node"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
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
		methodStore:     store.NewMethodStore(opts.Db, opts.NodeInfo.ID),
		ticker: tick.Ticker{
			Interval: b.Globals.PingInterval,
			Jitter:   b.Globals.PingJitter,
			Logger:   opts.Logger,
			Tracer:   otel.Tracer("", trace.WithInstrumentationAttributes(opts.Attributes...)),
		},
	}

	return handler, nil
}

type protocolHandlerJSONRPC struct {
	db             *database.Database
	logger         *zap.Logger
	serverURL      url.URL
	nodeInfo       node.Info
	numConnections int

	metrics *monitoring.Monitoring

	methodStore store.MethodStore

	dialer          gorillaWebsocket.Dialer
	connections     []*runtime.Conn
	capabilityNames []string
	ticker          tick.Ticker
}

func (s *protocolHandlerJSONRPC) IsConnected() bool {
	return len(s.connections) > 0
}

func (s *protocolHandlerJSONRPC) Run(ctx context.Context) error {
	ctx, span := monitoring.Tracer.Start(ctx, "jsonrpc-Run")
	defer span.End()

	err := s.storeNode(ctx)
	if err != nil {
		s.logger.Error("storing node in DB", zap.Error(err))
		return err
	}
	defer s.deleteNode(ctx)

	capabilitiesHeader, err := json.Marshal(s.capabilityNames)
	if err != nil {
		return err
	}

	reqHeader := http.Header{
		CapabilitiesHeaderKey: []string{string(capabilitiesHeader)},
	}

	snappy := websocket.NewSnappyCodec()
	s.connections = make([]*runtime.Conn, s.numConnections)

	var wg sync.WaitGroup

	for i := range s.numConnections {
		wsConn, resp, err := s.dialer.Dial(s.serverURL.String(), reqHeader)
		if err != nil {
			return fmt.Errorf("failed to dial connection #%d: %w", i, err)
		}
		_ = resp

		conn := runtime.NewConnection(websocket.NewWebsocketTransport(wsConn, snappy))
		s.connections[i] = conn
		conn.SetUserData(s.methodStore)
		err = s.registerCapabilities(conn, resp.Header.Get(CapabilitiesHeaderKey))
		if err != nil {
			return err
		}
		go func() {
			wg.Add(1)
			defer wg.Done()

			err := conn.ReaderLoop(ctx)
			s.connections[i] = nil
			if err != nil {
				s.logger.Error("connection closed", zap.Error(err), zap.Int("connection-number", i))
			}
		}()
	}
	s.ticker.Start(ctx, s.ping)

	wg.Wait()
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

func (s *protocolHandlerJSONRPC) ping(ctx context.Context) {
	ctx, span := monitoring.Tracer.Start(ctx, "ping")
	defer span.End()

	conn := findConn(s.connections)
	if conn == nil {
		err := fmt.Errorf("no open connection")
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.Error("can't ping", zap.Error(err))
		return
	}

	params := kong_sync.GetDeltaParams{
		NodeId:  s.nodeInfo.ID.String(),
		Version: s.getConfigurationVersion(ctx),
	}
	resp, err := kong_sync.CallGetDelta(ctx, s.connections[0], &params)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.methodStore.RecordErrorResponse(&params, err)
		return

	}
	s.methodStore.RecordMethodReturn(&params, resp)

	sync, err := kong_sync.FoldGetDeltaResultError(resp, err)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.Error("get delta error", zap.Error(err))
	}

	err = s.handleSync(ctx, sync)
	if err != nil {
		span.SetAttributes(attribute.String("error", err.Error()))
		s.logger.Error("handle sync error", zap.Error(err))
	}
}

func findConn(conns []*runtime.Conn) *runtime.Conn {
	for _, c := range conns {
		if c != nil {
			return c
		}
	}
	return nil
}

func (s *protocolHandlerJSONRPC) handleSync(ctx context.Context, sync *kong_sync.GetDeltaResult) error {
	ctx, span := monitoring.Tracer.Start(ctx, "handle-sync")
	defer span.End()

	for i, delta := range *sync {
		if err := s.applyDelta(ctx, delta); err != nil {
			s.logger.Warn("applying Delta", zap.Int("delta-number", i), zap.Error(err))
			return err
		}
	}

	return nil
}

func (s *protocolHandlerJSONRPC) storeNode(ctx context.Context) error {
	node := database.Node{
		// CipherSuite:      tls.CipherSuiteName(s.session.ConnectionState.CipherSuite),
		ControlPlaneHost: s.nodeInfo.Host,
		Hostname:         s.nodeInfo.Hostname,
		ID:               s.nodeInfo.ID.String(),
		Payload:          map[string]interface{}{},
		// TLSVersion:       node.TLSVersionString(s.session.ConnectionState.Version),
		Version: s.nodeInfo.Version.String(),
		Group:   s.nodeInfo.Group,
	}
	if err := s.db.SetNode(ctx, node); err != nil {
		return fmt.Errorf("failed to add node to database: %w", err)
	}
	return nil
}

func (s *protocolHandlerJSONRPC) deleteNode(ctx context.Context) {
	if err := s.db.DeleteNode(ctx, s.nodeInfo.Host, s.nodeInfo.ID); err != nil {
		s.logger.Error("unable to delete configuration", zap.Error(err))
	}
}

func (s *protocolHandlerJSONRPC) getConfigurationVersion(ctx context.Context) string {
	ctx, span := monitoring.Tracer.Start(ctx, "getConfigurationVersion")
	defer span.End()

	node, err := s.db.GetNode(ctx, s.nodeInfo.Host, s.nodeInfo.ID)
	if err != nil {
		s.logger.Error("unable to get node", zap.Error(err))
		return "0"
	}

	// Get the hash from the configuration or return a default 0's
	configurationHash, ok := node.Payload["config_hash"].(string)
	if !ok || len(configurationHash) == 0 {
		return "0"
	}
	return fmt.Sprintf("%v", configurationHash)
}

func (s *protocolHandlerJSONRPC) applyDelta(ctx context.Context, delta kong_sync.Delta) error {
	ctx, span := monitoring.Tracer.Start(ctx, "applyDelta")
	defer span.End()

	node, err := s.db.GetNode(ctx, s.nodeInfo.Host, s.nodeInfo.ID)
	if err != nil {
		return fmt.Errorf("unable to get node: %w", err)
	}

	configVersion, ok := node.Payload["config_hash"].(string)
	if !ok || len(configVersion) == 0 {
		configVersion = "0"
	}

	if delta.Version != configVersion {
		return fmt.Errorf("config version mismatch (%q != %q)", delta.Version, configVersion)
	}

	if node.Payload == nil {
		node.Payload = make(map[string]any)
	}

	if len(delta.Row) == 0 {
		removeConfigEntry(node.Payload, delta.Type, delta.Id)
	} else {
		setConfigEntry(node.Payload, delta.Type, delta.Id, delta.Row)
	}

	node.Payload["config_hash"] = delta.NewVersion

	err = s.db.SetNode(ctx, *node)

	return nil
}

func removeConfigEntry(payload map[string]any, entryType, id string) {
	table, ok := payload[entryType]
	if !ok || table == nil {
		return
	}

	entries, ok := table.(map[string]any)
	if !ok || entries == nil {
		return
	}

	delete(entries, id)
}

func setConfigEntry(payload map[string]any, entryType, id string, row any) {
	table, ok := payload[entryType]
	if !ok || table == nil {
		payload[entryType] = map[string]any{id: row}
		return
	}

	entries, ok := table.(map[string]any)
	if !ok || entries == nil {
		return
	}

	entries[id] = row
}

func (s *protocolHandlerJSONRPC) Close() error {
	for _, conn := range s.connections {
		conn.Close()
	}
	s.connections = nil
	return nil
}
