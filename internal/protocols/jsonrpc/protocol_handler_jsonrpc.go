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
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/mikefero/ankh"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/mikefero/kheper/node"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type HandlerBuilder struct {
	HandShakeTimeout time.Duration
	PingInterval     time.Duration
	PingJitter       time.Duration
}

func (b *HandlerBuilder) Build(opts node.ProtocolHandlerBuildOpts) (node.ProtocolHandler, error) {
	var err error

	handler := &protocolHandlerJSONRPC{
		db:           opts.Db,
		logger:       opts.Logger,
		nodeInfo:     opts.NodeInfo,
		pingInterval: b.PingInterval,
		pingJitter:   b.PingJitter,
		attributes:   opts.Attributes,
		metrics:      opts.Metrics,
	}

	handler.client, err = ankh.NewWebSocketClient(ankh.WebSocketClientOpts{
		Handler:          handler,
		HandShakeTimeout: b.HandShakeTimeout,
		ServerURL: url.URL{
			Scheme: "wss",
			Host:   fmt.Sprintf("%s:%d", opts.ConnectionOpts.Host, opts.ConnectionOpts.Port),
			Path:   "/v2/outlet",
			RawQuery: url.Values{
				"node_id":       []string{opts.NodeInfo.ID.String()},
				"node_hostname": []string{opts.ConnectionOpts.Host},
				"node_version":  []string{opts.NodeInfo.Version.String()},
			}.Encode(),
		},
		TLSConfig: opts.ConnectionOpts.TLSConfig,
	})
	if err != nil {
		return nil, err
	}

	return handler, nil
}

type protocolHandlerJSONRPC struct {
	db           *database.Database
	logger       *zap.Logger
	nodeInfo     node.Info
	client       *ankh.WebSocketClient
	pingInterval time.Duration
	pingJitter   time.Duration

	attributes []attribute.KeyValue
	metrics    *monitoring.Monitoring

	session *ankh.Session
}

func (s *protocolHandlerJSONRPC) IsConnected() bool {
	return s.client != nil && s.client.IsConnected()
}

func (s *protocolHandlerJSONRPC) Run(ctx context.Context) error {
	return nil
}

func (s *protocolHandlerJSONRPC) Close() error {
	if s.client == nil {
		return nil
	}

	return errors.New("not implemented")
}

func (s *protocolHandlerJSONRPC) OnConnectedHandler( /*resp*/ _ *http.Response, session *ankh.Session) error {
	s.session = session
	panic("not implemented")
}

func (s *protocolHandlerJSONRPC) OnDisconnectionHandler() {
	panic("not implemented")
}

func (s *protocolHandlerJSONRPC) OnDisconnectionErrorHandler( /*err*/ _ error) {
	panic("not implemented")
}

func (s *protocolHandlerJSONRPC) OnPongHandler( /*appData*/ _ string) {
	panic("not implemented")
}

func (s *protocolHandlerJSONRPC) OnReadMessageHandler( /*messageType*/ _ int /*message*/, _ []byte) {
	panic("not implemented")
}

func (s *protocolHandlerJSONRPC) OnReadMessageErrorHandler( /*err*/ _ error) {
	panic("not implemented")
}

func (s *protocolHandlerJSONRPC) OnReadMessagePanicHandler( /*err*/ _ error) {
	panic("not implemented")
}
