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
package node_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/mikefero/ankh"
	"github.com/mikefero/kheper/internal/protocols/ws"
	"github.com/mikefero/kheper/node"
	"github.com/ovechkin-dm/mockio/matchers"
	. "github.com/ovechkin-dm/mockio/mock"
	"github.com/stretchr/testify/require"

	"go.uber.org/zap"
)

func generateTestCertificates(t *testing.T) *tls.Config {
	t.Helper()

	privRSA, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatalf("failed to generate RSA private key: %v", err)
	}

	privECDSA, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA private key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"ankh"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(30 * time.Minute),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privRSA.PublicKey, privRSA)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privRSA)})
	certRSA, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load RSA key pair: %v", err)
	}

	derBytes, err = x509.CreateCertificate(rand.Reader, &template, &template, &privECDSA.PublicKey, privECDSA)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBytes, err := x509.MarshalECPrivateKey(privECDSA)
	if err != nil {
		t.Fatalf("failed to marshal ECDSA private key: %v", err)
	}
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes})
	certECDSA, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("failed to load EC key pair: %v", err)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{
			certRSA,
			certECDSA,
		},
		InsecureSkipVerify: true,
	}
}

func findUnusedLocalHostAndPort(t *testing.T) (string, int) {
	t.Helper()

	var address string
	for i := 0; i < 10; i++ {
		if listener, err := net.Listen("tcp", "localhost:0"); err == nil {
			address = listener.Addr().String()
			listener.Close()
			break
		}
	}
	if len(address) == 0 {
		t.Fatalf("failed to get random address after 10 attempts")
	}

	tokens := strings.Split(address, ":")
	if len(tokens) != 2 {
		t.Fatalf("invalid address: %s", address)
	}
	port, err := strconv.Atoi(tokens[1])
	if err != nil {
		t.Fatalf("invalid port: %s", tokens[1])
	}

	return tokens[0], port
}

func waitForServer(t *testing.T, address string, tlsConfig *tls.Config) {
	t.Helper()

	timeout := 10 * time.Second
	deadline := time.Now().Add(timeout)
	for {
		var conn net.Conn
		var err error

		conn, err = tls.Dial("tcp", address, tlsConfig)
		if err == nil {
			conn.Close()
		} else {
			return
		}

		if time.Now().After(deadline) {
			t.Fatalf("server at %s did not become available within %v", address, timeout)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func waitForCapture[T any](t *testing.T, captor matchers.ArgumentCaptor[T]) {
	t.Helper()

	defaultWaitForCapture := 10 * time.Millisecond
	waitForCapturStr := os.Getenv("KHEPER_TEST_WAIT_FOR_CAPTURE")
	waitForCapture := defaultWaitForCapture
	if len(waitForCapturStr) != 0 {
		var err error
		waitForCapture, err = time.ParseDuration(waitForCapturStr)
		if err != nil {
			t.Fatalf("failed to parse timeout from KHEPER_TEST_WAIT_FOR_CAPTURE: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 100; i++ {
			if len(captor.Values()) != 0 {
				return
			}
			time.Sleep(waitForCapture)
		}
	}()
	wg.Wait()
}

func waitFor(t *testing.T) {
	t.Helper()

	defaultWaitFor := 100 * time.Millisecond
	waitForStr := os.Getenv("KHEPER_TEST_WAIT_FOR")
	waitFor := defaultWaitFor
	if len(waitForStr) != 0 {
		var err error
		waitFor, err = time.ParseDuration(waitForStr)
		if err != nil {
			t.Fatalf("failed to parse timeout from KHEPER_TEST_WAIT_FOR: %v", err)
		}
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(waitFor)
	}()
	wg.Wait()
}

type mockServer struct {
	cancel       context.CancelFunc
	host         string
	mockHandlers []ankh.WebSocketServerEventHandler
	port         int
	serverURL    url.URL
	tlsConfig    *tls.Config
}

func createMockServer(t *testing.T) *mockServer {
	t.Helper()

	host, port := findUnusedLocalHostAndPort(t)
	address := fmt.Sprintf("%s:%d", host, port)
	serverURL := url.URL{
		Scheme: "wss",
		Host:   address,
	}
	standardHandler := Mock[ankh.WebSocketServerEventHandler]()
	jsonRPCHandler := Mock[ankh.WebSocketServerEventHandler]()
	tlsConfig := generateTestCertificates(t)
	opts := ankh.WebSocketServerOpts{
		Address:             address,
		IsKeepAlivesEnabled: true,
		PathHandlers: ankh.PathHandlers{
			"/v1/outlet": standardHandler,
			"/v2/outlet": jsonRPCHandler,
		},
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       5 * time.Second,
		ShutdownTimeout:   5 * time.Second,
		TLSConfig:         tlsConfig,
	}
	server, err := ankh.NewWebSocketServer(opts)
	if err != nil {
		t.Fatalf("failed to create WebSocket server: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		err := server.Run(ctx)
		require.NoError(t, err)
	}()
	waitForServer(t, address, tlsConfig)

	return &mockServer{
		host:   host,
		port:   port,
		cancel: cancel,
		mockHandlers: []ankh.WebSocketServerEventHandler{
			standardHandler,
			jsonRPCHandler,
		},
		serverURL: serverURL,
		tlsConfig: tlsConfig,
	}
}

func TestNode(t *testing.T) {

	t.Run("verify host is properly set", func(t *testing.T) {
		t.Parallel()

		n, err := node.NewNode(node.Opts{})
		require.ErrorContains(t, err, "invalid host")
		require.Nil(t, n)

		n, err = node.NewNode(node.Opts{
			Host: "invalid_host",
		})
		require.ErrorContains(t, err, "invalid host")
		require.Nil(t, n)
	})

	t.Run("verify port is properly set", func(t *testing.T) {
		t.Parallel()

		n, err := node.NewNode(node.Opts{
			Host: "localhost",
			Port: 0,
		})
		require.ErrorContains(t, err, "invalid port")
		require.Nil(t, n)

		n, err = node.NewNode(node.Opts{
			Host: "localhost",
			Port: 65536,
		})
		require.ErrorContains(t, err, "invalid port")
		require.Nil(t, n)
	})

	// t.Run("verify JSONRPC protocol is not supported", func(t *testing.T) {
	// 	t.Parallel()
	//
	// 	node, err := node.NewNode(node.Opts{
	// 		Host: "localhost",
	// 		Port: 3737,
	// 		// Protocol: node.JSONRPC,
	// 	})
	// 	require.ErrorContains(t, err, "JSONRPC is not supported")
	// 	require.Nil(t, node)
	// })

	t.Run("verify node ID must be set", func(t *testing.T) {
		t.Parallel()

		node, err := node.NewNode(node.Opts{
			Host:           "localhost",
			Port:           3737,
			HandlerBuilder: &ws.HandlerBuilder{},
		})
		require.ErrorContains(t, err, "node ID must be set")
		require.Nil(t, node)
	})

	t.Run("verify node hostname is properly set", func(t *testing.T) {
		t.Parallel()

		n, err := node.NewNode(node.Opts{
			Host:           "localhost",
			Port:           3737,
			HandlerBuilder: &ws.HandlerBuilder{},
			ID:             uuid.New(),
		})
		require.ErrorContains(t, err, "invalid hostname")
		require.Nil(t, n)

		n, err = node.NewNode(node.Opts{
			Host:           "localhost",
			Port:           3737,
			HandlerBuilder: &ws.HandlerBuilder{},
			ID:             uuid.New(),
			Hostname:       "invalid_hostname",
		})
		require.ErrorContains(t, err, "invalid hostname")
		require.Nil(t, n)
	})

	t.Run("verify ping interval is properly set", func(t *testing.T) {
		t.Parallel()

		node, err := node.NewNode(node.Opts{
			Host:           "localhost",
			Port:           3737,
			HandlerBuilder: &ws.HandlerBuilder{},
			Hostname:       "kheper.local",
			ID:             uuid.New(),
			Logger:         zap.NewNop(),
		})
		require.ErrorContains(t, err, "ping interval must be > 0")
		require.Nil(t, node)
	})

	t.Run("verify ping jitter is properly set", func(t *testing.T) {
		t.Parallel()

		node, err := node.NewNode(node.Opts{
			Host: "localhost",
			Port: 3737,
			HandlerBuilder: &ws.HandlerBuilder{
				PingInterval: 1,
			},
			Hostname: "kheper.local",
			ID:       uuid.New(),
			Logger:   zap.NewNop(),
		})
		require.ErrorContains(t, err, "ping jitter must be > 0")
		require.Nil(t, node)
	})

	t.Run("verify logger is set", func(t *testing.T) {
		t.Parallel()

		node, err := node.NewNode(node.Opts{
			Host: "localhost",
			Port: 3737,
			HandlerBuilder: &ws.HandlerBuilder{
				PingInterval: 1,
				PingJitter:   1,
			},
			Hostname: "kheper.local",
			ID:       uuid.New(),
		})
		require.ErrorContains(t, err, "logger must be set")
		require.Nil(t, node)
	})

	t.Run("verify node is created", func(t *testing.T) {
		t.Parallel()

		node, err := node.NewNode(node.Opts{
			Host: "localhost",
			Port: 3737,
			HandlerBuilder: &ws.HandlerBuilder{
				PingInterval: 1,
				PingJitter:   1,
			},
			Hostname: "kheper.local",
			ID:       uuid.New(),
			Logger:   zap.NewNop(),
		})
		require.NoError(t, err)
		require.NotNil(t, node)
	})

	t.Run("can start a node and connect to a control plane server and handle node events", func(t *testing.T) {
		t.Parallel()
		SetUp(t)

		mockServer := createMockServer(t)
		serverHandler := mockServer.mockHandlers[0]
		pingCaptor := Captor[string]()
		sessionCaptor := Captor[*ankh.Session]()
		When(serverHandler.OnConnectedHandler(Any[string](), sessionCaptor.Capture())).ThenReturn(nil)
		When(serverHandler.OnPingHandler(Any[string](), pingCaptor.Capture())).ThenReturn([]byte("control-plane")).ThenAnswer(nil)
		defer mockServer.cancel()

		logger := zap.NewNop()
		n, err := node.NewNode(node.Opts{
			Host:                    mockServer.host,
			Port:                    mockServer.port,
			RequiredPayloadEntities: []string{"routes"},
			Certificate:             mockServer.tlsConfig.Certificates[0],
			ID:                      uuid.New(),
			Hostname:                "kheper.local",
			HandlerBuilder: &ws.HandlerBuilder{
				HandshakeTimeout: 5 * time.Second,
				PingInterval:     100 * time.Millisecond,
				PingJitter:       1,
			},
			Logger: logger,
		})
		require.NoError(t, err)
		require.NotNil(t, n)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			err := n.Run(ctx)
			require.NoError(t, err)
		}()
		waitForCapture(t, sessionCaptor)
		waitForCapture(t, pingCaptor)
		require.NotNil(t, pingCaptor.Last())

		t.Log("ensure coverage for read handler")
		var buf bytes.Buffer
		gzipWriter := gzip.NewWriter(&buf)
		defer gzipWriter.Close()
		_, err = gzipWriter.Write([]byte(`{
			"config_hash": "1f764bed6e9dd06e1f764bed6e9dd06e",
			"config_table": {
				"services": [
					{
						"name": "service1"
					}
				]
			}
		}`))
		require.NoError(t, err)
		gzipWriter.Close()
		sessionCaptor.Last().Send(buf.Bytes())
		waitFor(t) // Wait for message to be received by the node

		cancel()
		waitFor(t) // Wait for the server handlers to be called
		dataCaptor := Captor[[]byte]()
		Verify(serverHandler, Once()).OnConnectionHandler(Any[http.ResponseWriter](), Any[*http.Request]())
		Verify(serverHandler, Once()).OnConnectedHandler(Any[string](), Any[*ankh.Session]())
		Verify(serverHandler, AtLeastOnce()).OnPingHandler(Any[string](), Exact(strings.Repeat("0", 32)))
		Verify(serverHandler, Once()).OnReadMessageHandler(Any[string](), Exact(websocket.BinaryMessage), dataCaptor.Capture())
		Verify(serverHandler, Once()).OnDisconnectionHandler(Any[string]())
		waitForCapture(t, dataCaptor)
		require.NotNil(t, dataCaptor.Last())

		t.Log("ensure basic_info message was sent to the control plane")
		var data map[string]interface{}
		err = json.Unmarshal(dataCaptor.Last(), &data)
		require.NoError(t, err)
		plugins, ok := data["plugins"]
		require.True(t, ok)
		require.NotNil(t, plugins)
		delete(data, "plugins")
		updateData, err := json.Marshal(data)
		require.NoError(t, err)
		require.JSONEq(t, `{"labels": {"kheper": "true"},"type": "basic_info"}`, string(updateData))
	})

	t.Run("verify a failure to start node", func(t *testing.T) {
		t.Parallel()
		SetUp(t)

		mockServer := createMockServer(t)
		serverHandler := mockServer.mockHandlers[0]
		When(serverHandler.OnConnectionHandler(Any[http.ResponseWriter](), Any[*http.Request]())).ThenReturn("", errors.New("connection denied"))
		defer mockServer.cancel()

		node, err := node.NewNode(node.Opts{
			Host:        mockServer.host,
			Port:        mockServer.port,
			Certificate: mockServer.tlsConfig.Certificates[0],
			ID:          uuid.New(),
			Hostname:    "kheper.local",
			HandlerBuilder: &ws.HandlerBuilder{
				HandshakeTimeout: 5 * time.Second,
				PingInterval:     1,
				PingJitter:       1,
			},
			Logger: zap.NewNop(),
		})
		require.NoError(t, err)
		require.NotNil(t, node)

		err = node.Run(context.Background())
		require.ErrorContains(t, err, "error occurred while running client")
	})

	t.Run("verify a node cannot be started twice", func(t *testing.T) {
		t.Parallel()
		SetUp(t)

		mockServer := createMockServer(t)
		serverHandler := mockServer.mockHandlers[0]
		sessionCaptor := Captor[*ankh.Session]()
		When(serverHandler.OnConnectedHandler(Any[string](), sessionCaptor.Capture())).ThenReturn(nil)
		defer mockServer.cancel()

		n, err := node.NewNode(node.Opts{
			Host:        mockServer.host,
			Port:        mockServer.port,
			Certificate: mockServer.tlsConfig.Certificates[0],
			ID:          uuid.New(),
			Hostname:    "kheper.local",
			HandlerBuilder: &ws.HandlerBuilder{
				HandshakeTimeout: 5 * time.Second,
				PingInterval:     15 * time.Second,
				PingJitter:       10 * time.Second,
			},
			Logger: zap.NewNop(),
		})
		require.NoError(t, err)
		require.NotNil(t, n)

		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go func() {
			err := n.Run(ctx)
			require.NoError(t, err)
		}()
		waitForCapture(t, sessionCaptor)
		require.NotNil(t, sessionCaptor.Last())

		err = n.Run(context.Background())
		require.Error(t, err)
		require.Equal(t, err, node.ErrNodeConnected)
	})

	t.Run("verify TLS connection states", func(t *testing.T) {
		t.Setenv("GODEBUG", "tlsrsakex=1") // enable RSA key exchange for testing
		ecCipherSuites := []uint16{
			// TLS v1.2 only cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256,

			// TLS v1.0 - v1.2 cipher suites
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
		}
		rsaCipherSuites := []uint16{
			// TLS v1.2 only cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,

			// TLS v1.0 - v1.2 cipher suites
			tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
			tls.TLS_RSA_WITH_AES_256_CBC_SHA,
		}
		allCipherSuites := append(ecCipherSuites, rsaCipherSuites...)

		server := func(t *testing.T, address string, tlsConfig *tls.Config, expectedCipherSuite uint16,
			expectedTLSVersion uint16) {
			config := &tls.Config{
				Certificates:       tlsConfig.Certificates,
				InsecureSkipVerify: true, // nolint: gosec
				MinVersion:         tls.VersionTLS12,
				MaxVersion:         tls.VersionTLS13,
				CipherSuites:       allCipherSuites,
			}
			listener, err := tls.Listen("tcp", address, config)
			require.NoError(t, err)
			defer listener.Close()
			conn, err := listener.Accept()
			require.NoError(t, err)
			defer conn.Close()
			tlsConn, ok := conn.(*tls.Conn)
			require.True(t, ok)
			require.NoError(t, tlsConn.Handshake())

			// Validate TLS version and cipher suite
			connState := tlsConn.ConnectionState()
			require.Equal(t, expectedTLSVersion, connState.Version)
			// Cipher suite cannot be set for TLS v1.3 by client
			if expectedTLSVersion != tls.VersionTLS13 {
				require.Equal(t, expectedCipherSuite, connState.CipherSuite)
			}
		}

		t.Run("verify TLS 1.3 is the default protocol", func(t *testing.T) {
			host, port := findUnusedLocalHostAndPort(t)
			address := fmt.Sprintf("%s:%d", host, port)
			tlsConfig := generateTestCertificates(t)
			wg := sync.WaitGroup{}
			wg.Add(1)
			go func() {
				defer wg.Done()
				server(t, address, tlsConfig, 0, tls.VersionTLS13)
			}()
			waitFor(t) // Wait for server to become available

			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			wg.Add(1)
			go func() {
				defer wg.Done()
				node, err := node.NewNode(node.Opts{
					Host:        host,
					Port:        port,
					Certificate: tlsConfig.Certificates[0],
					ID:          uuid.New(),
					Hostname:    "kheper.local",
					HandlerBuilder: &ws.HandlerBuilder{
						HandshakeTimeout: 5 * time.Second,
						PingInterval:     1,
						PingJitter:       1,
					},
					Logger: zap.NewNop(),
				})
				require.NoError(t, err)
				require.NotNil(t, node)

				// Ignore error here since the node will fail to connect as the server
				// is not a WebSocket server
				node.Run(ctx)
			}()
			wg.Wait()
		})

		t.Run("verify TLS 1.2 and cipher suites", func(t *testing.T) {
			for _, cipherSuite := range allCipherSuites {
				t.Run(tls.CipherSuiteName(cipherSuite), func(t *testing.T) {
					host, port := findUnusedLocalHostAndPort(t)
					address := fmt.Sprintf("%s:%d", host, port)
					tlsConfig := generateTestCertificates(t)
					wg := sync.WaitGroup{}
					wg.Add(1)
					go func() {
						defer wg.Done()
						server(t, address, tlsConfig, cipherSuite, tls.VersionTLS12)
					}()
					waitFor(t) // Wait for server to become available

					// Ensure elliptical curve is used for ECDSA cipher suites
					certificate := tlsConfig.Certificates[0]
					for _, e := range ecCipherSuites {
						if e == cipherSuite {
							certificate = tlsConfig.Certificates[1]
							break
						}
					}

					ctx, cancel := context.WithCancel(context.Background())
					defer cancel()
					wg.Add(1)
					go func() {
						defer wg.Done()
						node, err := node.NewNode(node.Opts{
							Host:        host,
							Port:        port,
							CipherSuite: cipherSuite,
							TLSVersion:  tls.VersionTLS12,
							Certificate: certificate,
							ID:          uuid.New(),
							Hostname:    "kheper.local",
							HandlerBuilder: &ws.HandlerBuilder{
								HandshakeTimeout: 5 * time.Second,
								PingInterval:     1,
								PingJitter:       1,
							},
							Logger: zap.NewNop(),
						})
						require.NoError(t, err)
						require.NotNil(t, node)

						// Ignore error here since the node will fail to connect as the server
						// is not a WebSocket server
						node.Run(ctx)
					}()
					wg.Wait()
				})
			}
		})
	})
}
