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
package main

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/kong/semver/v4"
	"github.com/mikefero/kheper/internal/config"
	"github.com/mikefero/kheper/internal/monitoring"
	"github.com/mikefero/kheper/internal/utils"
	"github.com/mikefero/kheper/node"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"go.uber.org/zap"
)

var (
	Version   string
	Commit    string
	OsArch    string
	GoVersion string
	BuildDate string
)

func main() {
	logger, err := zap.NewProduction()
	if err != nil {
		panic(fmt.Sprintf("unable to create logger: %v", err))
	}
	logger.Info("starting kheper",
		zap.String("version", Version),
		zap.String("commit", Commit),
		zap.String("os-arch", OsArch),
		zap.String("go-version", GoVersion),
		zap.String("build-date", BuildDate),
	)

	// Load the configuration
	config, err := config.NewConfig()
	if err != nil {
		panic(fmt.Sprintf("unable to create config: %v", err))
	}

	// Create a new context with a cancel function
	ctx, cancel := context.WithCancel(context.Background())

	// Handle user break signals
	breakSignal := make(chan os.Signal, 1)
	signal.Notify(breakSignal, os.Interrupt, syscall.SIGTERM)

	// Create a WaitGroup to ensure all nodes finish properly and are grouped in
	// creation by nodes
	instancesCreateWG := sync.WaitGroup{}
	nodeWG := sync.WaitGroup{}

	// Cleanup resources on exit
	defer cancel()
	defer close(breakSignal)

	// Create a jittered reconnection interval function
	nodeConfiguration := config.Globals.Node
	reconnectionInternal := func() time.Duration {
		jitter, err := rand.Int(rand.Reader, big.NewInt(nodeConfiguration.ReconnectionJitter.Nanoseconds()))
		if err != nil {
			logger.Error("unable to generate jitter", zap.Error(err))
			jitter = big.NewInt(0)
		}
		logger.Debug("reconnection interval",
			zap.Duration("interval", nodeConfiguration.ReconnectionInterval),
			zap.Duration("jitter", time.Duration(jitter.Int64())),
		)
		return nodeConfiguration.ReconnectionInterval + time.Duration(jitter.Int64())
	}

	// Handle metric collection
	metrics, err := monitoring.NewMonitoring(monitoring.Opts{
		OpenTelemetry: config.OpenTelemetry,
		Logger:        logger,
	})
	if err != nil {
		panic(fmt.Errorf("error creating monitoring: %w", err))
	}

	// Create the nodes from the configuration. In order to ensure that user
	// break signals are handled properly and the nodes are created in a goroutine.
	for _, n := range config.Nodes {
		// Verify the protocol is valid
		protocol, err := node.Parse(n.Connection.Protocol)
		if err != nil {
			panic(fmt.Sprintf("unable to validate protocol %s: %v", n.Connection.Protocol, err))
		}

		// Generate the X509 key pair to verify valid certificate
		certificate, err := tls.X509KeyPair([]byte(n.Connection.Certificate), []byte(n.Connection.Key))
		if err != nil {
			panic(fmt.Sprintf("unable to parse X509 key pair: %v", err))
		}

		// Verify the TLS version is valid
		var tlsVersion uint16
		if len(n.Connection.TLSVersion) > 0 {
			tlsVersion, err = utils.TLSVersion(n.Connection.TLSVersion)
			if err != nil {
				panic(fmt.Sprintf("invalid TLS version: %v", err))
			}
		}

		// Create the node instances in a goroutine
		instancesCreateWG.Add(1)
		go func() {
			defer instancesCreateWG.Done()

			// Create the nodes
			for i := 0; i < n.Instances; i++ {
				select {
				case <-ctx.Done():
					return
				default:
					// Verify the cipher suite is valid
					var cipherSuite uint16
					if len(n.Connection.CipherSuites) > 0 {
						// Set the cipher suite using a round-robin strategy
						cipherSuiteStr := n.Connection.CipherSuites[i%len(n.Connection.CipherSuites)]
						cipherSuite, err = utils.CipherSuite(cipherSuiteStr)
						if err != nil {
							panic(fmt.Sprintf("invalid cipher suite: %v", err))
						}

						// Ensure cipher suite is supported by TLS v1.0 - v1.2
						if tlsVersion != tls.VersionTLS13 &&
							cipherSuite != 0 &&
							!utils.ValidateCipherSuite(cipherSuite, tlsVersion) {
							panic(fmt.Sprintf("cipher suite %s is not supported by TLS version %s",
								cipherSuiteStr, n.Connection.TLSVersion))
						}
					}

					// Set the version using a round-robin strategy and verify it is valid
					versionStr := n.Versions[i%len(n.Versions)]
					version, err := semver.Parse(versionStr)
					if err != nil {
						panic(fmt.Sprintf("unable to validate node version %s: %v", versionStr, err))
					}

					// Set the hostname or generate a sequential one based on the index
					hostname := n.Hostname
					if strings.ToLower(n.Hostname) == "sequential" {
						hostname = fmt.Sprintf("kheper-%d.local", i+1)
					}

					// Set the node ID, generate a sequential one or generate a unique one
					// based on the index
					var nodeID uuid.UUID
					switch strings.ToLower(n.ID) {
					case "sequential":
						nodeID, err = uuid.Parse(fmt.Sprintf("00000000-0000-4000-8000-%012x", i+1))
						if err != nil {
							panic(fmt.Sprintf("unable to parse node ID %s: %v", nodeID, err))
						}
					case "unique":
						nodeID = uuid.New()
					default:
						nodeID, err = uuid.Parse(n.ID)
						if err != nil {
							panic(fmt.Sprintf("unable to parse node ID %s: %v", nodeID, err))
						}
					}

					// Create the node options
					nodeOpts := node.Opts{
						ID:                      nodeID,
						Hostname:                hostname,
						Version:                 version,
						Protocol:                protocol,
						Host:                    n.Connection.Host,
						Port:                    n.Connection.Port,
						Group:                   n.Group,
						CipherSuite:             cipherSuite,
						TLSVersion:              tlsVersion,
						RequiredPayloadEntities: n.RequiredPayloadEntities,
						Certificate:             certificate,
						HandshakeTimeout:        nodeConfiguration.HandshakeTimeout,
						PingInterval:            nodeConfiguration.PingInterval,
						PingJitter:              nodeConfiguration.PingJitter,
						APIConfiguration:        &config.API,
						OpenTelemetry:           config.OpenTelemetry,
						Logger:                  logger,
					}

					// Create the node
					node, err := node.NewNode(nodeOpts)
					if err != nil {
						panic(fmt.Sprintf("unable to create node: %v", err))
					}

					// Run the node with reconnection logic
					nodeWG.Add(1)
					go func() {
						defer nodeWG.Done()

						// Create the metric attributes for the retry connection count
						var metricAttributes []attribute.KeyValue
						metricAttributes = []attribute.KeyValue{
							attribute.String("host", n.Connection.Host),
							attribute.String("hostname", hostname),
							attribute.String("node-id", nodeID.String()),
							attribute.String("version", version.String()),
						}
						if n.Group != nil {
							metricAttributes = append(metricAttributes, attribute.String("group", *n.Group))
						}
						metricOptions := metric.WithAttributes(metricAttributes...)

						for {
							select {
							case <-ctx.Done():
								return
							default:
								if err := node.Run(ctx); err != nil {
									logger.Warn("node run failed, attempting to reconnect", zap.Error(err))
									select {
									case <-ctx.Done():
										return
									case <-time.After(reconnectionInternal()):
										metrics.RetryConnectionCount.Add(context.Background(), 1, metricOptions)
										continue
									}
								}

								// Handle node restarts if the context is not done; usually this
								// indicates the server has been terminated
								select {
								case <-ctx.Done():
									return
								default:
									select {
									case <-ctx.Done():
										return
									case <-time.After(reconnectionInternal()):
										continue
									}
								}
							}
						}
					}()

					// Delay the next instance creation if it's not the last one or the
					// context is done
					if i < n.Instances-1 {
						select {
						case <-ctx.Done():
							return
						case <-time.After(nodeConfiguration.NodeCreationDelay):
						}
					}
				}
			}
		}()
	}

	// Wait for a signal
	<-breakSignal
	logger.Info("user requested shutdown")
	metrics.Shutdown(ctx)
	cancel()
	instancesCreateWG.Wait()
	nodeWG.Wait()
}
