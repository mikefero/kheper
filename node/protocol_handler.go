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

	"github.com/google/uuid"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"go.opentelemetry.io/otel/attribute"
	"go.uber.org/zap"
)

type ProtocolHandler interface {
	IsConnected() bool
	Run(ctx context.Context) error
	Close() error
}

type ProtocolHandlerBuildOpts struct {
	ID             uuid.UUID
	Db             *database.Database
	Logger         *zap.Logger
	ConnectionOpts ConnectionOpts
	NodeInfo       Info
	Metrics        *monitoring.Monitoring
	Attributes     []attribute.KeyValue
}

type ConnectionOpts struct {
	Host      string
	Port      int
	TLSConfig *tls.Config
}

type ProtocolHandlerBuilder interface {
	Build(opts ProtocolHandlerBuildOpts) (ProtocolHandler, error)
}

func TLSVersionString(version uint16) string {
	switch version {
	case tls.VersionTLS10:
		return "TLS 1.0"
	case tls.VersionTLS11:
		return "TLS 1.1"
	case tls.VersionTLS12:
		return "TLS 1.2"
	case tls.VersionTLS13:
		return "TLS 1.3"
	default:
		return "Unknown"
	}
}
