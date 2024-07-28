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
package server_test

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gavv/httpexpect/v2"
	"github.com/google/uuid"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/server"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func findUnusedLocalPort(t *testing.T) int {
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

	return port
}

func TestServer(t *testing.T) {
	db, err := database.NewDatabase()
	require.NoError(t, err)
	require.NotNil(t, db)

	port := findUnusedLocalPort(t)
	serverOpts := server.Opts{
		Database:          db,
		Port:              port,
		ReadTimeout:       5 * time.Second,
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      5 * time.Second,
		Logger:            zap.NewNop(),
	}

	t.Run("verify error occurs when database is not set", func(t *testing.T) {
		s, err := server.NewServer(server.Opts{})
		require.ErrorContains(t, err, "database must be set")
		require.Nil(t, s)
	})

	t.Run("verify error occurs when port is not set", func(t *testing.T) {
		s, err := server.NewServer(server.Opts{
			Database: db,
		})
		require.ErrorContains(t, err, "invalid port")
		require.Nil(t, s)
	})

	t.Run("verify error occurs when read timeout is not set", func(t *testing.T) {
		s, err := server.NewServer(server.Opts{
			Database: db,
			Port:     findUnusedLocalPort(t),
		})
		require.ErrorContains(t, err, "read timeout must be > 0")
		require.Nil(t, s)
	})

	t.Run("verify error occurs when read header timeout is not set", func(t *testing.T) {
		s, err := server.NewServer(server.Opts{
			Database:    db,
			Port:        findUnusedLocalPort(t),
			ReadTimeout: 5 * time.Second,
		})
		require.ErrorContains(t, err, "read header timeout must be > 0")
		require.Nil(t, s)
	})

	t.Run("verify error occurs when write timeout is not set", func(t *testing.T) {
		s, err := server.NewServer(server.Opts{
			Database:          db,
			Port:              findUnusedLocalPort(t),
			ReadTimeout:       5 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
		})
		require.ErrorContains(t, err, "write timeout must be > 0")
		require.Nil(t, s)
	})

	t.Run("verify error occurs when logger is not set", func(t *testing.T) {
		s, err := server.NewServer(server.Opts{
			Database:          db,
			Port:              findUnusedLocalPort(t),
			ReadTimeout:       5 * time.Second,
			ReadHeaderTimeout: 5 * time.Second,
			WriteTimeout:      5 * time.Second,
		})
		require.ErrorContains(t, err, "logger must be set")
		require.Nil(t, s)
	})

	t.Run("verify server is created", func(t *testing.T) {
		s, err := server.NewServer(serverOpts)
		require.NoError(t, err)
		require.NotNil(t, s)
	})

	t.Run("verify server is created only once", func(t *testing.T) {
		s, err := server.NewServer(serverOpts)
		require.NoError(t, err)
		require.NotNil(t, s)
		s2, err := server.NewServer(serverOpts)
		require.NoError(t, err)
		require.NotNil(t, s2)
		require.Equal(t, s, s2)
	})

	t.Run("verify requests and responses are handled properly", func(t *testing.T) {
		s, err := server.NewServer(serverOpts)
		require.NoError(t, err)
		require.NotNil(t, s)

		// Start the server
		wg := sync.WaitGroup{}
		wg.Add(1)
		ctx, cancel := context.WithCancel(context.Background())
		defer wg.Wait()
		defer cancel()
		defer s.Close()
		go func() {
			defer wg.Done()

			serverCloseCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()

			if err := s.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				require.NoError(t, err)
				return
			}
			if err := s.Shutdown(serverCloseCtx); err != nil {
				require.NoError(t, err)
			}
		}()

		// Create the client
		client := httpexpect.Default(t, fmt.Sprintf("http://localhost:%d", port))

		t.Run("verify groups are empty when no groups are available", func(t *testing.T) {
			client.GET("/v1/groups").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEmpty()
		})

		t.Run("verify a single group is available", func(t *testing.T) {
			id := uuid.New()
			group := "test"
			err := db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3",
			})
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			client.GET("/v1/groups").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsOnly("test")
		})

		t.Run("verify multiple groups are available", func(t *testing.T) {
			node1ID := uuid.New()
			group1 := "test-1"
			node2ID := uuid.New()
			group2 := "test-2"
			err := db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "localhost",
				Group:            &group1,
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3",
			})
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "kheper.example.com",
				Group:            &group2,
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3.1",
			})
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			client.GET("/v1/groups").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsAll("test-1", "test-2")
		})

		t.Run("verify a single node is available within a group", func(t *testing.T) {
			id := uuid.New()
			group := "test"
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				Group:            &group,
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node.CipherSuite,
					"group":        group,
					"hostname":     node.Hostname,
					"id":           id,
					"tls_version":  node.TLSVersion,
					"version":      node.Version,
				},
			}
			client.GET("/v1/groups/test").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
		})

		t.Run("verify multiple nodes are available within a group", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			group := "test"
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "localhost", node2ID)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node1.CipherSuite,
					"group":        group,
					"hostname":     node1.Hostname,
					"id":           node1ID,
					"tls_version":  node1.TLSVersion,
					"version":      node1.Version,
				},
				{
					"cipher_suite": node2.CipherSuite,
					"group":        group,
					"hostname":     node2.Hostname,
					"id":           node2ID,
					"tls_version":  node2.TLSVersion,
					"version":      node2.Version,
				},
			}
			client.GET("/v1/groups/test").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsOnly(expected[0], expected[1])
		})

		t.Run("verify different nodes are available within different groups", func(t *testing.T) {
			node1ID := uuid.New()
			group1 := "test-1"
			node2ID := uuid.New()
			group2 := "test-2"
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Group:            &group1,
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "kheper.example.com",
				Group:            &group2,
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node1.CipherSuite,
					"group":        group1,
					"hostname":     node1.Hostname,
					"id":           node1ID,
					"tls_version":  node1.TLSVersion,
					"version":      node1.Version,
				},
			}
			client.GET("/v1/groups/test-1").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
			expected = []map[string]interface{}{
				{
					"cipher_suite": node2.CipherSuite,
					"group":        group2,
					"hostname":     node2.Hostname,
					"id":           node2ID,
					"tls_version":  node2.TLSVersion,
					"version":      node2.Version,
				},
			}
			client.GET("/v1/groups/test-2").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
		})

		t.Run("verify hosts are empty when no hosts are available", func(t *testing.T) {
			client.GET("/v1/hosts").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEmpty()
		})

		t.Run("verify a single host is available", func(t *testing.T) {
			id := uuid.New()
			err := db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3",
			})
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			client.GET("/v1/hosts").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsOnly(map[string]interface{}{"hostname": "localhost"})
		})

		t.Run("verify multiple hosts are available", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			err := db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3",
			})
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "kheper.example.com",
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3.1",
			})
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			client.GET("/v1/hosts").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsAll(
					map[string]interface{}{"hostname": "localhost"},
					map[string]interface{}{"hostname": "kheper.example.com"},
				)
		})

		t.Run("verify group is available in hosts if set", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			group := "test"
			err := db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3",
			})
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), database.Node{
				ControlPlaneHost: "kheper.example.com",
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				Version:          "1.2.3.1",
			})
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			client.GET("/v1/hosts").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsAll(
					map[string]interface{}{"hostname": "localhost", "groups": []string{"test"}},
					map[string]interface{}{"hostname": "kheper.example.com"},
				)
		})

		t.Run("verify nodes are empty when no hosts are available", func(t *testing.T) {
			expected := `{
				"message": "resource not found: host"
			}`
			r := client.GET("/v1/hosts/localhost").
				Expect().
				Status(http.StatusNotFound)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify a single node is available", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node.CipherSuite,
					"hostname":     node.Hostname,
					"id":           id,
					"tls_version":  node.TLSVersion,
					"version":      node.Version,
				},
			}
			client.GET("/v1/hosts/localhost").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
		})

		t.Run("verify multiple nodes are available", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "localhost", node2ID)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node1.CipherSuite,
					"hostname":     node1.Hostname,
					"id":           node1ID,
					"tls_version":  node1.TLSVersion,
					"version":      node1.Version,
				},
				{
					"cipher_suite": node2.CipherSuite,
					"hostname":     node2.Hostname,
					"id":           node2ID,
					"tls_version":  node2.TLSVersion,
					"version":      node2.Version,
				},
			}
			client.GET("/v1/hosts/localhost").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				ContainsOnly(expected[0], expected[1])
		})

		t.Run("verify different nodes are available with different hosts", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "kheper.example.com",
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node1.CipherSuite,
					"hostname":     node1.Hostname,
					"id":           node1ID,
					"tls_version":  node1.TLSVersion,
					"version":      node1.Version,
				},
			}
			client.GET("/v1/hosts/localhost").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
			expected = []map[string]interface{}{
				{
					"cipher_suite": node2.CipherSuite,
					"hostname":     node2.Hostname,
					"id":           node2ID,
					"tls_version":  node2.TLSVersion,
					"version":      node2.Version,
				},
			}
			client.GET("/v1/hosts/kheper.example.com").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
		})

		t.Run("verify group is available in nodes if set", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			group := "test"
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "kheper.example.com",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			expected := []map[string]interface{}{
				{
					"cipher_suite": node1.CipherSuite,
					"hostname":     node1.Hostname,
					"id":           node1ID,
					"tls_version":  node1.TLSVersion,
					"version":      node1.Version,
				},
			}
			client.GET("/v1/hosts/localhost").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
			expected = []map[string]interface{}{
				{
					"cipher_suite": node2.CipherSuite,
					"group":        group,
					"hostname":     node2.Hostname,
					"id":           node2ID,
					"tls_version":  node2.TLSVersion,
					"version":      node2.Version,
				},
			}
			client.GET("/v1/hosts/kheper.example.com").
				Expect().
				Status(http.StatusOK).
				JSON().
				Array().
				IsEqual(expected)
		})

		t.Run("verify a node can be retrieved", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := map[string]interface{}{
				"cipher_suite": node.CipherSuite,
				"hostname":     node.Hostname,
				"id":           id,
				"payload":      node.Payload,
				"tls_version":  node.TLSVersion,
				"version":      node.Version,
			}
			client.GET("/v1/hosts/localhost/{id}", id).
				Expect().
				Status(http.StatusOK).
				JSON().
				Object().
				IsEqual(expected)
		})

		t.Run("verify a node can be retrieved with a group if set", func(t *testing.T) {
			id := uuid.New()
			group := "test"
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := map[string]interface{}{
				"cipher_suite": node.CipherSuite,
				"group":        group,
				"hostname":     node.Hostname,
				"id":           id,
				"payload":      node.Payload,
				"tls_version":  node.TLSVersion,
				"version":      node.Version,
			}
			client.GET("/v1/hosts/localhost/{id}", id).
				Expect().
				Status(http.StatusOK).
				JSON().
				Object().
				IsEqual(expected)
		})

		t.Run("verify different nodes are available within the same host", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "localhost", node2ID)

			expected := map[string]interface{}{
				"cipher_suite": node1.CipherSuite,
				"hostname":     node1.Hostname,
				"id":           node1ID,
				"payload":      node1.Payload,
				"tls_version":  node1.TLSVersion,
				"version":      node1.Version,
			}
			client.GET("/v1/hosts/localhost/{id}", node1ID).
				Expect().
				Status(http.StatusOK).
				JSON().
				Object().
				IsEqual(expected)
			expected = map[string]interface{}{
				"cipher_suite": node2.CipherSuite,
				"hostname":     node2.Hostname,
				"id":           node2ID,
				"payload":      node2.Payload,
				"tls_version":  node2.TLSVersion,
				"version":      node2.Version,
			}
			client.GET("/v1/hosts/localhost/{id}", node2ID).
				Expect().
				Status(http.StatusOK).
				JSON().
				Object().
				IsEqual(expected)
		})

		t.Run("verify different nodes are available within different hosts", func(t *testing.T) {
			node1ID := uuid.New()
			node2ID := uuid.New()
			node1 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               node1ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			node2 := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "kheper.example.com",
				Hostname:         "kheper.local",
				ID:               node2ID.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3.1",
			}
			err := db.SetNode(context.TODO(), node1)
			require.NoError(t, err)
			err = db.SetNode(context.TODO(), node2)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", node1ID)
			defer db.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

			expected := map[string]interface{}{
				"cipher_suite": node1.CipherSuite,
				"hostname":     node1.Hostname,
				"id":           node1ID,
				"payload":      node1.Payload,
				"tls_version":  node1.TLSVersion,
				"version":      node1.Version,
			}
			client.GET("/v1/hosts/localhost/{id}", node1ID).
				Expect().
				Status(http.StatusOK).
				JSON().
				Object().
				IsEqual(expected)
			expected = map[string]interface{}{
				"cipher_suite": node2.CipherSuite,
				"hostname":     node2.Hostname,
				"id":           node2ID,
				"payload":      node2.Payload,
				"tls_version":  node2.TLSVersion,
				"version":      node2.Version,
			}
			client.GET("/v1/hosts/kheper.example.com/{id}", node2ID).
				Expect().
				Status(http.StatusOK).
				JSON().
				Object().
				IsEqual(expected)
		})

		t.Run("verify nodes is not found when node ID is not available", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"message": "resource not found: node"
			}`
			r := client.GET("/v1/hosts/localhost/{id}", uuid.NewString()).
				Expect().
				Status(http.StatusNotFound)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify node is not found for resource when node is not valid", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"message": "resource not found: node"
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", uuid.NewString()).
				Expect().
				Status(http.StatusNotFound)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify internal server error for resource config_table is not available", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload:          map[string]interface{}{"is_valid": true},
				TLSVersion:       "TLSv1.3",
				Version:          "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"detail": "internal server error: unable to retrieve config_table",
				"status": 500,
				"title": "Internal Server Error"
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", id).
				Expect().
				Status(http.StatusInternalServerError)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify resource is not found for when resource is not available", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload: map[string]interface{}{
					"config_table": map[string]interface{}{
						"stuff": map[string]interface{}{},
					},
				},
				TLSVersion: "TLSv1.3",
				Version:    "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"message": "resource not found: services"
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", id).
				Expect().
				Status(http.StatusNotFound)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify internal server error for resource when config_table is not valid map[string]interface{}", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload: map[string]interface{}{
					"config_table": "invalid",
				},
				TLSVersion: "TLSv1.3",
				Version:    "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"detail": "internal server error: unable to cast config_table",
				"status": 500,
				"title": "Internal Server Error"
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", id).
				Expect().
				Status(http.StatusInternalServerError)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify internal server error for resource when resources is not valid []interface{}", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload: map[string]interface{}{
					"config_table": map[string]interface{}{
						"services": "invalid",
					},
				},
				TLSVersion: "TLSv1.3",
				Version:    "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"detail": "internal server error: unable to cast resources",
				"status": 500,
				"title": "Internal Server Error"
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", id).
				Expect().
				Status(http.StatusInternalServerError)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify internal server error for resource when resource is not valid map[string]interface{}", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload: map[string]interface{}{
					"config_table": map[string]interface{}{
						"services": []interface{}{
							"invalid",
						},
					},
				},
				TLSVersion: "TLSv1.3",
				Version:    "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"detail": "internal server error: unable to cast resource",
				"status": 500,
				"title": "Internal Server Error"
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", id).
				Expect().
				Status(http.StatusInternalServerError)
			r.Header("Content-Type").IsEqual("application/problem+json")
			require.JSONEq(t, expected, r.Body().Raw())
		})

		t.Run("verify resources are available for a node", func(t *testing.T) {
			id := uuid.New()
			node := database.Node{
				CipherSuite:      "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
				ControlPlaneHost: "localhost",
				Hostname:         "kheper.local",
				ID:               id.String(),
				Payload: map[string]interface{}{
					"config_table": map[string]interface{}{
						"services": []interface{}{
							map[string]interface{}{
								"name": "service1",
							},
							map[string]interface{}{
								"name": "service2",
							},
						},
						"routes": []interface{}{
							map[string]interface{}{
								"name": "route1",
							},
							map[string]interface{}{
								"name": "route2",
							},
						},
					},
				},
				TLSVersion: "TLSv1.3",
				Version:    "1.2.3",
			}
			err := db.SetNode(context.TODO(), node)
			require.NoError(t, err)
			defer db.DeleteNode(context.TODO(), "localhost", id)

			expected := `{
				"data": [
					{
						"name": "service1"
					},
					{
						"name": "service2"
					}
				],
				"next": null
			}`
			r := client.GET("/v1/hosts/localhost/{id}/services", id).
				Expect().
				Status(http.StatusOK)
			r.Header("Content-Type").IsEqual("application/json")
			require.JSONEq(t, expected, r.Body().Raw())

			expected = `{
				"data": [
					{
						"name": "route1"
					},
					{
						"name": "route2"
					}
				],
				"next": null
			}`
			r = client.GET("/v1/hosts/localhost/{id}/routes", id).
				Expect().
				Status(http.StatusOK)
			r.Header("Content-Type").IsEqual("application/json")
			require.JSONEq(t, expected, r.Body().Raw())
		})
	})
}
