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
package ws

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/mikefero/ankh"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/mikefero/kheper/node"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
)

var (
	defaultConfigurationHash = strings.Repeat("0", 32)
	nodes                    = map[string]int64{}
	nodesMutex               sync.Mutex

	ErrNotConnected = errors.New("not Connected")
)

type HandlerBuilder struct {
	HandshakeTimeout time.Duration
	PingInterval     time.Duration
	PingJitter       time.Duration
}

func (b *HandlerBuilder) Build(opts node.ProtocolHandlerBuildOpts) (node.ProtocolHandler, error) {
	var err error

	if b.PingInterval <= 0 {
		return nil, errors.New("ping interval must be > 0")
	}
	if b.PingJitter <= 0 {
		return nil, errors.New("ping jitter must be > 0")
	}

	handler := &protocolHandlerStandard{
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
		HandShakeTimeout: b.HandshakeTimeout,
		ServerURL: url.URL{
			Scheme: "wss",
			Host:   fmt.Sprintf("%s:%d", opts.ConnectionOpts.Host, opts.ConnectionOpts.Port),
			Path:   "/v1/outlet",
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

type protocolHandlerStandard struct {
	cancel       context.CancelFunc
	db           *database.Database
	logger       *zap.Logger
	nodeInfo     node.Info
	pingInterval time.Duration
	pingJitter   time.Duration

	attributes []attribute.KeyValue
	metrics    *monitoring.Monitoring

	client  *ankh.WebSocketClient
	session *ankh.Session

	// once is used to ensure that the node responds to a new configuration with a
	// ping immediately after receiving it.
	once sync.Once
}

func (s *protocolHandlerStandard) IsConnected() bool {
	return s.client != nil && s.client.IsConnected()
}

func (s *protocolHandlerStandard) Run(ctx context.Context) error {
	if s.client == nil {
		return ErrNotConnected
	}

	return s.client.Run(ctx)
}

func (s *protocolHandlerStandard) OnConnectedHandler(_ *http.Response, session *ankh.Session) error {
	ctx, span := monitoring.Tracer.Start(context.Background(), "OnConnectedHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	hostCount, groupCount, totalCount := addNode(ctx, s.nodeInfo.Host, s.nodeInfo.Group)
	s.metrics.HostConnectionGauge.Record(ctx, hostCount,
		metric.WithAttributes(attribute.String("host", s.nodeInfo.Host)))
	if s.nodeInfo.Group != nil {
		s.metrics.GroupConnectionGauge.Record(ctx, groupCount,
			metric.WithAttributes(attribute.String("group", *s.nodeInfo.Group)))
	}
	s.metrics.ConnectionGauge.Record(ctx, totalCount, metric.WithAttributes(s.attributes...))

	s.logger.Info("connected")
	s.session = session
	if err := sendInfo(ctx, session, s.nodeInfo); err != nil {
		return fmt.Errorf("unable to send info message: %w", err)
	}

	// Add the node to the database
	node := database.Node{
		CipherSuite:      tls.CipherSuiteName(s.session.ConnectionState.CipherSuite),
		ControlPlaneHost: s.nodeInfo.Host,
		Hostname:         s.nodeInfo.Hostname,
		ID:               s.nodeInfo.ID.String(),
		Payload:          map[string]interface{}{},
		TLSVersion:       node.TLSVersionString(s.session.ConnectionState.Version),
		Version:          s.nodeInfo.Version.String(),
		Group:            s.nodeInfo.Group,
	}
	if err := s.db.SetNode(ctx, node); err != nil {
		return fmt.Errorf("failed to add node to database: %w", err)
	}

	// Create a jittered ping interval function
	pingInterval := func() time.Duration {
		jitter, err := rand.Int(rand.Reader, big.NewInt(s.pingJitter.Nanoseconds()))
		if err != nil {
			s.logger.Error("unable to generate jitter", zap.Error(err))
			jitter = big.NewInt(0)
		}
		s.logger.Debug("ping interval",
			zap.Duration("interval", s.pingInterval),
			zap.Duration("jitter", time.Duration(jitter.Int64())),
		)
		return s.pingInterval + time.Duration(jitter.Int64())
	}

	// Start the ping interval
	pingCtx, pingCancel := context.WithCancel(context.Background())
	s.cancel = pingCancel
	go func() {
		defer pingCancel()

		for {
			select {
			case <-pingCtx.Done():
				return
			case <-time.After(pingInterval()):
				pingIntervalCtx, span := otel.Tracer("").Start(pingCtx, "ping-interval",
					trace.WithAttributes(s.attributes...))
				if err := s.ping(pingIntervalCtx); err != nil {
					s.logger.Error("unable to send ping", zap.Error(err))
				}
				span.End()
			}
		}
	}()

	return nil
}

func (s *protocolHandlerStandard) OnDisconnectionHandler() {
	ctx, span := monitoring.Tracer.Start(context.Background(), "OnDisconnectionHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	hostCount, groupCount, totalCount := removeNode(ctx, s.nodeInfo.Host, s.nodeInfo.Group)
	s.metrics.HostConnectionGauge.Record(ctx, hostCount,
		metric.WithAttributes(attribute.String("host", s.nodeInfo.Host)))
	if s.nodeInfo.Group != nil {
		s.metrics.GroupConnectionGauge.Record(ctx, groupCount,
			metric.WithAttributes(attribute.String("group", *s.nodeInfo.Group)))
	}
	s.metrics.ConnectionGauge.Record(ctx, totalCount, metric.WithAttributes(s.attributes...))

	if err := s.db.DeleteNode(ctx, s.nodeInfo.Host, s.nodeInfo.ID); err != nil {
		s.logger.Error("unable to delete configuration", zap.Error(err))
	}
	s.logger.Info("disconnected")
}

func (s *protocolHandlerStandard) OnDisconnectionErrorHandler(err error) {
	ctx, span := monitoring.Tracer.Start(context.Background(), "OnDisconnectionErrorHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	s.metrics.DisconnectionErrorCount.Add(ctx, 1, metric.WithAttributes(s.attributes...))

	s.logger.Error("disconnection error", zap.Error(err))
}

func (s *protocolHandlerStandard) OnPongHandler(appData string) {
	ctx, span := monitoring.Tracer.Start(context.Background(),
		"OnPongHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	s.metrics.PongCount.Add(ctx, 1, metric.WithAttributes(s.attributes...))

	if len(appData) > 0 {
		s.logger.Debug("pong", zap.String("app-data", appData))
	} else {
		s.logger.Debug("pong")
	}
}

func (s *protocolHandlerStandard) OnReadMessageHandler(messageType int, message []byte) {
	ctx, span := monitoring.Tracer.Start(context.Background(), "OnReadMessageHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	span.SetAttributes(attribute.Float64("compressed-size", float64(len(message))/1024))
	s.metrics.ReadMessageCount.Add(ctx, 1, metric.WithAttributes(s.attributes...))

	// Unzip and parse the message into a configuration format
	s.logger.Debug("read message", zap.Int("message-type", messageType))
	s.metrics.UncompressedSize.Record(ctx, float64(len(message))/1024, metric.WithAttributes(s.attributes...))
	reader, err := gzip.NewReader(bytes.NewReader(message))
	if err != nil {
		s.logger.Error("failed to create gzip reader to unzip message", zap.Error(err))
		return
	}
	bytes, err := io.ReadAll(reader)
	if err != nil {
		s.logger.Error("failed to read contents of gzip reader to unzip message", zap.Error(err))
		return
	}
	span.SetAttributes(attribute.Float64("uncompressed-size", float64(len(bytes))/1024))
	s.metrics.UncompressedSize.Record(ctx, float64(len(bytes))/1024, metric.WithAttributes(s.attributes...))
	var configuration map[string]interface{}
	if err := json.Unmarshal(bytes, &configuration); err != nil {
		s.logger.Error("failed to unmarshal configuration", zap.Error(err))
		return
	}
	span.SetAttributes(attribute.String("hash", fmt.Sprintf("%v", configuration["config_hash"])))

	// Check if the configuration is missing required payload entities
	missingRequiredPayloadEntities := []string{}
	ct, ok := configuration["config_table"]
	if !ok {
		span.SetAttributes(attribute.String("error", "missing config_table field in configuration"))
		s.logger.Error("missing config_table field in configuration")
		s.metrics.MissingRequiredPayloadEntities.Add(ctx, 1, metric.WithAttributes(s.attributes...))
	}
	configTable, ok := ct.(map[string]interface{})
	if !ok {
		span.SetAttributes(attribute.String("error", "config_table field in configuration is not a JSON object"))
		s.logger.Error("config_table field in configuration is not a JSON object")
		s.metrics.MissingRequiredPayloadEntities.Add(ctx, 1, metric.WithAttributes(s.attributes...))
	} else {
		for _, requiredPayloadEntity := range s.nodeInfo.RequiredPayloadEntities {
			if _, ok := configTable[requiredPayloadEntity]; !ok {
				span.SetAttributes(attribute.String("error", "missing required payload entity"),
					attribute.String("entity", requiredPayloadEntity))
				s.logger.Error("missing required payload entity", zap.String("entity", requiredPayloadEntity))
				missingRequiredPayloadEntities = append(missingRequiredPayloadEntities, requiredPayloadEntity)
				attributes := s.attributes
				attributes = append(attributes, attribute.String("entity", requiredPayloadEntity))
				s.metrics.MissingRequiredPayloadEntities.Add(ctx, 1, metric.WithAttributes(attributes...))
			}
		}
	}

	// Set the node configuration
	node := database.Node{
		CipherSuite:                    tls.CipherSuiteName(s.session.ConnectionState.CipherSuite),
		ControlPlaneHost:               s.nodeInfo.Host,
		Group:                          s.nodeInfo.Group,
		Hostname:                       s.nodeInfo.Hostname,
		ID:                             s.nodeInfo.ID.String(),
		Payload:                        configuration,
		TLSVersion:                     node.TLSVersionString(s.session.ConnectionState.Version),
		MissingRequiredPayloadEntities: missingRequiredPayloadEntities,
		Version:                        s.nodeInfo.Version.String(),
	}
	if err := s.db.SetNode(ctx, node); err != nil {
		s.logger.Error("failed to set configuration", zap.Error(err))
		return
	}
	s.logger.Debug("configuration", zap.Any("configuration", configuration))
	s.logger.Info("configuration updated", zap.Any("hash", configuration["config_hash"]))

	// Respond immediately with a ping when receiving a new configuration
	s.once.Do(func() {
		if err := s.ping(ctx); err != nil {
			s.logger.Error("unable to send ping", zap.Error(err))
		}
	})
}

func (s *protocolHandlerStandard) OnReadMessageErrorHandler(err error) {
	ctx, span := monitoring.Tracer.Start(context.Background(), "OnReadMessageErrorHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	s.metrics.ReadMessageErrorCount.Add(ctx, 1, metric.WithAttributes(s.attributes...))

	s.logger.Error("read message error", zap.Error(err))
}

func (s *protocolHandlerStandard) OnReadMessagePanicHandler(err error) {
	ctx, span := monitoring.Tracer.Start(context.Background(), "OnReadMessagePanicHandler",
		trace.WithAttributes(s.attributes...))
	defer span.End()
	s.metrics.ReadMessagePanicCount.Add(ctx, 1, metric.WithAttributes(s.attributes...))

	s.logger.Error("read message panic", zap.Error(err))
}

func (s *protocolHandlerStandard) Close() error {
	_, span := monitoring.Tracer.Start(context.Background(), "close",
		trace.WithAttributes(s.attributes...))
	defer span.End()

	if s.session == nil {
		return errors.New("client session is unavailable")
	}

	// Stop the ping interval
	if s.cancel != nil {
		s.cancel()
	}

	s.logger.Debug("closing")
	s.session.Close()
	return nil
}

func (s *protocolHandlerStandard) ping(ctx context.Context) error {
	ctx, span := monitoring.Tracer.Start(ctx, "ping")
	defer span.End()
	s.metrics.PingCount.Add(ctx, 1, metric.WithAttributes(s.attributes...))

	if s.session == nil {
		return errors.New("client session is unavailable")
	}

	configurationHash := s.getConfigurationHash()
	if err := s.session.Ping([]byte(configurationHash)); err != nil {
		return fmt.Errorf("failed to send ping: %w", err)
	}
	s.logger.Debug("ping", zap.String("config-hash", configurationHash))
	return nil
}

func sendInfo(ctx context.Context, session *ankh.Session, info node.Info) error {
	ctx, span := monitoring.Tracer.Start(ctx, "sendInfo")
	defer span.End()

	// Create the basic info message
	basicInfo := node.GetStandardBasicInfo(ctx, info.Version.String())
	jsonBasicInfo, err := json.Marshal(basicInfo)
	if err != nil {
		return fmt.Errorf("unable to marshal basic info message: %w", err)
	}
	if err := session.Send(jsonBasicInfo); err != nil {
		return fmt.Errorf("unable to write websocket message: %w", err)
	}
	return nil
}

func (s *protocolHandlerStandard) getConfigurationHash() string {
	ctx, span := monitoring.Tracer.Start(context.Background(), "getConfigurationHash")
	defer span.End()

	node, err := s.db.GetNode(ctx, s.nodeInfo.Host, s.nodeInfo.ID)
	if err != nil {
		s.logger.Error("unable to get node", zap.Error(err))
		return defaultConfigurationHash
	}

	// Get the hash from the configuration or return a default 0's
	configurationHash, ok := node.Payload["config_hash"].(string)
	if !ok || len(configurationHash) == 0 {
		return defaultConfigurationHash
	}
	return fmt.Sprintf("%v", configurationHash)
}

func addNode(ctx context.Context, host string, group *string) (int64, int64, int64) {
	_, span := monitoring.Tracer.Start(ctx, "addNode")
	defer span.End()

	nodesMutex.Lock()
	defer nodesMutex.Unlock()

	nodes[host]++
	nodes["total"]++
	var groupCount int64
	if group != nil {
		nodes[*group]++
		groupCount = nodes[*group]
	}
	return nodes[host], groupCount, nodes["total"]
}

func removeNode(ctx context.Context, host string, group *string) (int64, int64, int64) {
	_, span := monitoring.Tracer.Start(ctx, "removeNode")
	defer span.End()

	nodesMutex.Lock()
	defer nodesMutex.Unlock()

	nodes[host]--
	nodes["total"]--
	var groupCount int64
	if group != nil {
		nodes[*group]--
		groupCount = nodes[*group]
	}
	return nodes[host], groupCount, nodes["total"]
}
