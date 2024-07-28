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
package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/mikefero/kheper/internal/api"
	"github.com/mikefero/kheper/internal/database"
	"github.com/mikefero/kheper/internal/monitoring"
	openapi_types "github.com/oapi-codegen/runtime/types"
	"go.uber.org/zap"
)

type v1Hosts struct {
	Hostname string   `json:"hostname"`
	Groups   []string `json:"groups,omitempty"`
}

type v1HostNode struct {
	CipherSuite string             `json:"cipher_suite"`
	Group       *string            `json:"group,omitempty"`
	Hostname    string             `json:"hostname"`
	ID          openapi_types.UUID `json:"id"`
	TLSVersion  string             `json:"tls_version"`
	Version     string             `json:"version"`
}

type v1Node struct {
	CipherSuite string                 `json:"cipher_suite"`
	Group       *string                `json:"group,omitempty"`
	Hostname    string                 `json:"hostname"`
	ID          openapi_types.UUID     `json:"id"`
	Payload     map[string]interface{} `json:"payload"`
	TLSVersion  string                 `json:"tls_version"`
	Version     string                 `json:"version"`
}

func (h *handler) GetV1Groups(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoring.Tracer.Start(r.Context(), "GetV1Groups")
	defer span.End()

	groups, err := h.db.GetGroups(ctx)
	if err != nil {
		h.logger.Error("unable to retrieve groups",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(groups)
	if err != nil {
		h.logger.Error("unable to encode groups response",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	}
}

//nolint:dupl
func (h *handler) GetV1GroupsGroup(w http.ResponseWriter, r *http.Request, group api.GroupParameter) {
	ctx, span := monitoring.Tracer.Start(r.Context(), "GetV1GroupsGroup")
	defer span.End()

	nodes, err := h.db.GetNodesByGroup(ctx, group)
	if err != nil && !errors.Is(err, database.ErrHostNotFound) {
		h.logger.Error("unable to retrieve nodes",
			zap.String("group", group),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	} else if errors.Is(err, database.ErrHostNotFound) {
		h.logger.Debug("group not found",
			zap.String("group", group),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(ctx, w, r, "group")
		return
	}

	// Create the host nodes response
	hostNodesResponse := []v1HostNode{}
	for _, node := range nodes {
		id, err := uuid.Parse(node.ID)
		if err != nil {
			// This should never be able to happen due to index on schema for node ID
			h.logger.Error("unable to parse node ID",
				zap.String("group", group),
				zap.String("node-id", node.ID),
				zap.String("method", r.Method),
				zap.String("remote-address", r.RemoteAddr),
				zap.String("url", r.URL.String()),
				zap.Error(err))
			h.internalServerError(ctx, w, r, err)
			return
		}
		cipherSuite := node.CipherSuite
		hostname := node.Hostname
		tlsVersion := node.TLSVersion
		version := node.Version
		hostNodesResponse = append(hostNodesResponse, v1HostNode{
			ID:          id,
			CipherSuite: cipherSuite,
			Group:       node.Group,
			Hostname:    hostname,
			TLSVersion:  tlsVersion,
			Version:     version,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(hostNodesResponse)
	if err != nil {
		h.logger.Error("unable to encode nodes response",
			zap.String("group", group),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		return
	}
}

// GetHosts will return a list of all hosts connected to control plane(s) using
// the in-memory database and return them as a JSON response.
func (h *handler) GetV1Hosts(w http.ResponseWriter, r *http.Request) {
	ctx, span := monitoring.Tracer.Start(r.Context(), "GetV1Hosts")
	defer span.End()

	hosts, err := h.db.GetHosts(ctx)
	if err != nil {
		h.logger.Error("unable to retrieve hosts",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	}

	hostsResponse := []v1Hosts{}
	for _, host := range hosts {
		hostsResponse = append(hostsResponse, v1Hosts{
			Hostname: host.Hostname,
			Groups:   host.Groups,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(hostsResponse)
	if err != nil {
		h.logger.Error("unable to encode hosts response",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	}
}

// GetHost will return a list of all nodes connected to a control plane host
// using the in-memory database and return them as a JSON response.
//
//nolint:dupl
func (h *handler) GetV1HostsHost(w http.ResponseWriter, r *http.Request, host api.HostParameter) {
	ctx, span := monitoring.Tracer.Start(r.Context(), "GetV1HostsHost")
	defer span.End()

	nodes, err := h.db.GetNodesByHost(ctx, host)
	if err != nil && !errors.Is(err, database.ErrHostNotFound) {
		h.logger.Error("unable to retrieve nodes",
			zap.String("host", host),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	} else if errors.Is(err, database.ErrHostNotFound) {
		h.logger.Debug("host not found",
			zap.String("host", host),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(ctx, w, r, "host")
		return
	}

	// Create the host nodes response
	hostNodesResponse := []v1HostNode{}
	for _, node := range nodes {
		id, err := uuid.Parse(node.ID)
		if err != nil {
			// This should never be able to happen due to index on schema for node ID
			h.logger.Error("unable to parse node ID",
				zap.String("host", host),
				zap.String("node-id", node.ID),
				zap.String("method", r.Method),
				zap.String("remote-address", r.RemoteAddr),
				zap.String("url", r.URL.String()),
				zap.Error(err))
			h.internalServerError(ctx, w, r, err)
			return
		}
		cipherSuite := node.CipherSuite
		hostname := node.Hostname
		tlsVersion := node.TLSVersion
		version := node.Version
		hostNodesResponse = append(hostNodesResponse, v1HostNode{
			ID:          id,
			CipherSuite: cipherSuite,
			Group:       node.Group,
			Hostname:    hostname,
			TLSVersion:  tlsVersion,
			Version:     version,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(hostNodesResponse)
	if err != nil {
		h.logger.Error("unable to encode nodes response",
			zap.String("host", host),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		return
	}
}

// GetHostNodeId will return a node from the in-memory database and return it as
// a JSON response.
//
//nolint:dupl,revive,stylecheck
func (h *handler) GetV1HostsHostNodeId(w http.ResponseWriter, r *http.Request, host api.HostParameter,
	nodeId api.NodeIdParameter,
) {
	ctx, span := monitoring.Tracer.Start(r.Context(), "GetV1HostsHostNodeId")
	defer span.End()

	node, err := h.db.GetNode(ctx, host, nodeId)
	if err != nil && !errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Error("unable to retrieve node",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	} else if errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Debug("node not found",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(ctx, w, r, "node")
		return
	}

	// Create the node response
	nodeResponse := v1Node{
		ID:          nodeId,
		CipherSuite: node.CipherSuite,
		Group:       node.Group,
		Hostname:    node.Hostname,
		Payload:     node.Payload,
		TLSVersion:  node.TLSVersion,
		Version:     node.Version,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(nodeResponse)
	if err != nil {
		h.logger.Error("unable to encode node response",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		return
	}
}

// GetHostNodeIdResource will return a specific resource from a node payload
// from the in-memory database and return it as a JSON response.
//
//nolint:dupl,revive,stylecheck
func (h *handler) GetV1HostsHostNodeIdResource(w http.ResponseWriter, r *http.Request, host api.HostParameter,
	nodeId api.NodeIdParameter, resource api.ResourcesParameter,
) {
	ctx, span := monitoring.Tracer.Start(r.Context(), "GetV1HostsHostNodeIdResource")
	defer span.End()

	node, err := h.db.GetNode(ctx, host, nodeId)
	if err != nil && !errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Error("unable to retrieve node payload",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(ctx, w, r, err)
		return
	} else if errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Debug("node not found",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(ctx, w, r, "node")
		return
	}

	// Get the config_table from the payload
	configTableInterface, ok := node.Payload["config_table"]
	if !ok {
		h.logger.Error("unable to retrieve config_table",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("resource", resource),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.internalServerError(ctx, w, r, errors.New("unable to retrieve config_table"))
		return
	}
	configTable, ok := configTableInterface.(map[string]interface{})
	if !ok {
		h.logger.Error("unable to cast config_table",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("resource", resource),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.internalServerError(ctx, w, r, errors.New("unable to cast config_table"))
		return
	}

	// Get the resources from the config_table for the specified resource
	resourcesInterface, ok := configTable[resource]
	if !ok {
		h.logger.Debug("unable to retrieve resources",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("resource", resource),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(ctx, w, r, resource)
		return
	}
	resources, ok := resourcesInterface.([]interface{})
	if !ok {
		h.logger.Error("unable to cast resources",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("resource", resource),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.internalServerError(ctx, w, r, errors.New("unable to cast resources"))
		return
	}

	// Create the resources response
	data := []map[string]interface{}{}
	for _, resourceInterface := range resources {
		d, ok := resourceInterface.(map[string]interface{})
		if !ok {
			h.logger.Error("unable to cast resource",
				zap.String("host", host),
				zap.String("node-id", nodeId.String()),
				zap.String("resource", resource),
				zap.String("method", r.Method),
				zap.String("remote-address", r.RemoteAddr),
				zap.String("url", r.URL.String()))
			h.internalServerError(ctx, w, r, errors.New("unable to cast resource"))
			return
		}
		data = append(data, d)
	}
	resourceResponse := api.Resources{
		Data: &data,
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(resourceResponse)
	if err != nil {
		h.logger.Error("unable to encode resource response",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		return
	}
}

func (h *handler) internalServerError(ctx context.Context, w http.ResponseWriter, r *http.Request, err error) {
	_, span := monitoring.Tracer.Start(ctx, "internalServerError")
	defer span.End()

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusInternalServerError)
	detailMessage := fmt.Sprintf("internal server error: %v", err)
	err = json.NewEncoder(w).Encode(api.Error{
		Status: http.StatusInternalServerError,
		Title:  http.StatusText(http.StatusInternalServerError),
		Detail: detailMessage,
	})
	if err != nil {
		h.logger.Error("unable to encode internal server error response",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
	}
}

func (h *handler) notFoundError(ctx context.Context, w http.ResponseWriter, r *http.Request, resource string) {
	_, span := monitoring.Tracer.Start(ctx, "notFoundError")
	defer span.End()

	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusNotFound)
	errMessage := fmt.Sprintf("resource not found: %s", resource)
	err := json.NewEncoder(w).Encode(api.ResourceNotFound{
		Message: &errMessage,
	})
	if err != nil {
		h.logger.Error("unable to encode internal server error response",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
	}
}
