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
	"net/http"
	"time"

	"github.com/mikefero/ankh"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type protocolHandlerJSONRPC struct {
	protocolHandler

	db           *database.Database
	logger       *zap.Logger
	nodeInfo     Info
	pingInterval time.Duration
	pingJitter   time.Duration

	attributes []attribute.KeyValue
	metrics    *monitoring.Monitoring

	session *ankh.Session
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
