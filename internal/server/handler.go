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
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/google/uuid"
	"github.com/mikefero/kheper/internal/api"
	"github.com/mikefero/kheper/internal/database"
	"go.uber.org/zap"
)

// GetHosts will return a list of all hosts connected to control plane(s) using
// the in-memory database and return them as a JSON response.
func (h *handler) GetHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := h.db.GetHosts()
	if err != nil {
		h.logger.Error("unable to retrieve hosts",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(w, r, err)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	err = json.NewEncoder(w).Encode(hosts)
	if err != nil {
		h.logger.Error("unable to encode hosts response",
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(w, r, err)
		return
	}
}

// GetHost will return a list of all nodes connected to a control plane host
// using the in-memory database and return them as a JSON response.
func (h *handler) GetHost(w http.ResponseWriter, r *http.Request, host api.HostParameter) {
	nodes, err := h.db.GetNodes(host)
	if err != nil && !errors.Is(err, database.ErrHostNotFound) {
		h.logger.Error("unable to retrieve nodes",
			zap.String("host", host),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(w, r, err)
		return
	} else if errors.Is(err, database.ErrHostNotFound) {
		h.logger.Debug("host not found",
			zap.String("host", host),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(w, r, "host")
		return
	}

	// Create the host nodes response
	hostNodesResponse := api.HostNodesResponse{}
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
			h.internalServerError(w, r, err)
			return
		}
		hostname := node.Hostname
		version := node.Version
		hostNodesResponse = append(hostNodesResponse, api.HostNode{
			Id:       &id,
			Hostname: &hostname,
			Version:  &version,
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
//nolint:revive,stylecheck
func (h *handler) GetHostNodeId(w http.ResponseWriter, r *http.Request, host api.HostParameter,
	nodeId api.NodeIdParameter,
) {
	node, err := h.db.GetNode(host, nodeId)
	if err != nil && !errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Error("unable to retrieve node",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(w, r, err)
		return
	} else if errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Debug("node not found",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(w, r, "node")
		return
	}

	// Create the node response
	nodeResponse := api.Node{
		Hostname: &node.Hostname,
		Id:       &nodeId,
		Payload:  &node.Payload,
		Version:  &node.Version,
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
//nolint:revive,stylecheck
func (h *handler) GetHostNodeIdResource(w http.ResponseWriter, r *http.Request, host api.HostParameter,
	nodeId api.NodeIdParameter, resource api.ResourcesParameter,
) {
	node, err := h.db.GetNode(host, nodeId)
	if err != nil && !errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Error("unable to retrieve node payload",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()),
			zap.Error(err))
		h.internalServerError(w, r, err)
		return
	} else if errors.Is(err, database.ErrNodeNotFound) {
		h.logger.Debug("node not found",
			zap.String("host", host),
			zap.String("node-id", nodeId.String()),
			zap.String("method", r.Method),
			zap.String("remote-address", r.RemoteAddr),
			zap.String("url", r.URL.String()))
		h.notFoundError(w, r, "node")
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
		h.internalServerError(w, r, errors.New("unable to retrieve config_table"))
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
		h.internalServerError(w, r, errors.New("unable to cast config_table"))
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
		h.notFoundError(w, r, resource)
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
		h.internalServerError(w, r, errors.New("unable to cast resources"))
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
			h.internalServerError(w, r, errors.New("unable to cast resource"))
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

func (h *handler) internalServerError(w http.ResponseWriter, r *http.Request, err error) {
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

func (h *handler) notFoundError(w http.ResponseWriter, r *http.Request, resource string) {
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
