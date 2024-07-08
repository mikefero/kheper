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
	"github.com/mikefero/kheper/internal/utils"
	"github.com/mikefero/kheper/node"
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
	reconnectionInternal := func() time.Duration {
		jitter, err := rand.Int(rand.Reader, big.NewInt(config.Defaults.ReconnectionJitter.Nanoseconds()))
		if err != nil {
			logger.Error("unable to generate jitter", zap.Error(err))
			jitter = big.NewInt(0)
		}
		logger.Debug("reconnection interval",
			zap.Duration("interval", config.Defaults.ReconnectionInterval),
			zap.Duration("jitter", time.Duration(jitter.Int64())),
		)
		return config.Defaults.ReconnectionInterval + time.Duration(jitter.Int64())
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
			panic(fmt.Sprintf("unable to generate X509 key pair: %v", err))
		}

		// Validate the cipher suite and TLS version
		var cipherSuite uint16
		var tlsVersion uint16
		if len(n.Connection.CipherSuite) > 0 {
			cipherSuite, err = utils.CipherSuite(n.Connection.CipherSuite)
			if err != nil {
				panic(fmt.Sprintf("invalid cipher suite: %v", err))
			}
		}
		if len(n.Connection.TLSVersion) > 0 {
			tlsVersion, err = utils.TLSVersion(n.Connection.TLSVersion)
			if err != nil {
				panic(fmt.Sprintf("invalid TLS version: %v", err))
			}
		}
		// Ensure cipher suite is supported by TLS v1.0 - v1.2
		if tlsVersion != tls.VersionTLS13 &&
			cipherSuite != 0 &&
			!utils.IsCipherSuiteValid(cipherSuite, tlsVersion) {
			panic(fmt.Sprintf("cipher suite %s is not supported by TLS version %s",
				n.Connection.CipherSuite, n.Connection.TLSVersion))
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
					// Verify the node version is valid
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
						ID:                  nodeID,
						Hostname:            hostname,
						Version:             version,
						Protocol:            protocol,
						Host:                n.Connection.Host,
						Port:                n.Connection.Port,
						CipherSuite:         cipherSuite,
						TLSVersion:          tlsVersion,
						Certificate:         certificate,
						HandshakeTimeout:    config.Defaults.HandshakeTimeout,
						PingInterval:        config.Defaults.PingInterval,
						PingJitter:          config.Defaults.PingJitter,
						ServerConfiguration: &config.Server,
						Logger:              logger,
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
						case <-time.After(config.Defaults.NodeCreationDelay):
						}
					}
				}
			}
		}()
	}

	// Wait for a signal
	<-breakSignal
	logger.Info("user requested shutdown")
	cancel()
	instancesCreateWG.Wait()
	nodeWG.Wait()
}
