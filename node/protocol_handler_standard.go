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
	"strings"
	"sync"
	"time"

	"github.com/mikefero/ankh"
	"github.com/mikefero/kheper/internal/database"
	"go.uber.org/zap"
)

var defaultConfigurationHash = strings.Repeat("0", 32)

type protocolHandlerStandard struct {
	cancel       context.CancelFunc
	db           *database.Database
	logger       *zap.Logger
	nodeInfo     Info
	pingInterval time.Duration
	pingJitter   time.Duration
	session      *ankh.Session

	// once is used to ensure that the node responds to a new configuration with a
	// ping immediately after receiving it.
	once sync.Once
}

func (s *protocolHandlerStandard) OnConnectedHandler(_ *http.Response, session *ankh.Session) error {
	s.logger.Info("connected")
	s.session = session
	if err := sendInfo(session, s.nodeInfo); err != nil {
		return fmt.Errorf("unable to send info message: %w", err)
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
	ctx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	go func() {
		defer cancel()

		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(pingInterval()):
				if err := s.ping(); err != nil {
					s.logger.Error("unable to send ping", zap.Error(err))
				}
			}
		}
	}()

	return nil
}

func (s *protocolHandlerStandard) OnDisconnectionHandler() {
	if err := s.db.DeleteNode(s.nodeInfo.Host, s.nodeInfo.ID); err != nil {
		s.logger.Error("unable to delete configuration", zap.Error(err))
	}
	s.logger.Info("disconnected")
}

func (s *protocolHandlerStandard) OnDisconnectionErrorHandler(err error) {
	s.logger.Error("disconnection error", zap.Error(err))
}

func (s *protocolHandlerStandard) OnPongHandler(appData string) {
	if len(appData) > 0 {
		s.logger.Debug("pong", zap.String("app-data", appData))
	} else {
		s.logger.Debug("pong")
	}
}

func (s *protocolHandlerStandard) OnReadMessageHandler(messageType int, message []byte) {
	// Unzip and parse the message into a configuration format
	s.logger.Debug("read message", zap.Int("message-type", messageType))
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
	var configuration map[string]interface{}
	if err := json.Unmarshal(bytes, &configuration); err != nil {
		s.logger.Error("failed to unmarshal configuration", zap.Error(err))
		return
	}

	// Set the configuration
	payload := database.Node{
		CipherSuite:      tls.CipherSuiteName(s.session.ConnectionState.CipherSuite),
		ControlPlaneHost: s.nodeInfo.Host,
		Group:            s.nodeInfo.Group,
		Hostname:         s.nodeInfo.Hostname,
		ID:               s.nodeInfo.ID.String(),
		Payload:          configuration,
		TLSVersion:       tlsVersionString(s.session.ConnectionState.Version),
		Version:          s.nodeInfo.Version.String(),
	}
	if err := s.db.SetNode(payload); err != nil {
		s.logger.Error("failed to set configuration", zap.Error(err))
		return
	}
	s.logger.Debug("configuration", zap.Any("configuration", configuration))
	s.logger.Info("configuration updated", zap.Any("hash", configuration["config_hash"]))

	// Respond immediately with a ping when receiving a new configuration
	s.once.Do(func() {
		if err := s.ping(); err != nil {
			s.logger.Error("unable to send ping", zap.Error(err))
		}
	})
}

func (s *protocolHandlerStandard) OnReadMessageErrorHandler(err error) {
	s.logger.Error("read message error", zap.Error(err))
}

func (s *protocolHandlerStandard) OnReadMessagePanicHandler(err error) {
	s.logger.Error("read message panic", zap.Error(err))
}

func (s *protocolHandlerStandard) close() error {
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

func (s *protocolHandlerStandard) ping() error {
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

func sendInfo(session *ankh.Session, info Info) error {
	basicInfo := GetStandardBasicInfo(info.Version.String())
	jsonBasicInfo, err := json.Marshal(basicInfo)
	if err != nil {
		return fmt.Errorf("unable to marshal basic info message: %w", err)
	}
	if err := session.Send(jsonBasicInfo); err != nil {
		return fmt.Errorf("unable to write websocket message: %w", err)
	}
	return nil
}

func tlsVersionString(version uint16) string {
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

func (s *protocolHandlerStandard) getConfigurationHash() string {
	node, err := s.db.GetNode(s.nodeInfo.Host, s.nodeInfo.ID)
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
