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
package database

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"

	"github.com/google/uuid"
	"github.com/hashicorp/go-memdb"
	"github.com/mikefero/kheper/internal/monitoring"
)

var (
	// ErrHostNotFound is returned when a host is not found.
	ErrHostNotFound = errors.New("host not found")
	// ErrNodeNotFound is returned when a node is not found.
	ErrNodeNotFound = errors.New("node not found")

	singleton *Database
	once      sync.Once
)

// Database is the database for the node to store data in.
type Database struct {
	db *memdb.MemDB
}

// Hosts is the definition of a host. It contains information about the host and
// the groups that the host is a member of.
type Hosts struct {
	// Hostname is the hostname of the host.
	Hostname string
	// Groups is a list of groups that the host is a member of.
	Groups []string
}

// Node is the definition of a node for the database. It contains information
// about the node and the payload configuration sent from the control plane.
type Node struct {
	// CipherSuite is the TLS cipher suite used when establishing a connection to
	// the control plane.
	CipherSuite string
	// ControlPlaneHost is the RFC 1123 IP address or hostname of the control
	// plane connected to.
	ControlPlaneHost string
	// Group is the name of the group to which the node instance belongs.
	Group *string
	// Hostname is the RFC 1123 hostname of the node.
	Hostname string
	// ID is the unique ID of the node.
	ID string
	// Payload is the payload sent from the control plane.
	Payload map[string]interface{}
	// TLSVersion is the TLS version used when establishing a connection to the
	// control plane.
	TLSVersion string
	// MissingRequiredPayloadEntities is the list of entities that are missing
	// from the configuration payload sent from the control plane.
	MissingRequiredPayloadEntities []string
	// Version is the Kong Gateway semantic version of the node. This version
	// can be represented as 3 or 4 integers separated by dots (e.g. 1.2.3 or
	// 1.2.3.4).
	Version string
}

// StringPtrIndex is a custom indexer that can handle nil string pointers.
type StringPtrIndex struct {
	// Field is the name of the field to index.
	Field string
}

// FromObject implements the memdb.Indexer interface.
func (s *StringPtrIndex) FromObject(obj interface{}) (bool, []byte, error) {
	v := reflect.ValueOf(obj)
	if v.Kind() == reflect.Ptr {
		v = v.Elem()
	}
	val := v.FieldByName(s.Field)
	if !val.IsValid() {
		return false, nil, fmt.Errorf("field %s not found", s.Field)
	}
	if val.IsNil() {
		return true, []byte{}, nil
	}

	b, ok := val.Interface().(*string)
	if !ok {
		return false, nil, fmt.Errorf("field %s is not a string", s.Field)
	}
	return true, []byte(*b), nil
}

// FromArgs implements the memdb.Indexer interface.
func (s *StringPtrIndex) FromArgs(args ...interface{}) ([]byte, error) {
	if len(args) != 1 {
		return nil, fmt.Errorf("expected one argument, got %d", len(args))
	}

	arg, ok := args[0].(string)
	if !ok {
		return nil, fmt.Errorf("expected string argument, got %T", args[0])
	}
	return []byte(arg), nil
}

// NewDatabase creates a new database for the node to store data in. This
// function is safe to call multiple times and will only create the database
// once. Ensure that upon error the application is properly terminated.
func NewDatabase() (*Database, error) {
	// Create the database if it hasn't been created yet
	var err error
	once.Do(func() {
		// Initialize the database singleton
		singleton = &Database{}

		// Create the database schema
		schema := &memdb.DBSchema{
			Tables: map[string]*memdb.TableSchema{
				"node": {
					Name: "node",
					Indexes: map[string]*memdb.IndexSchema{
						"id": {
							Name:   "id",
							Unique: true,
							Indexer: &memdb.CompoundIndex{
								Indexes: []memdb.Indexer{
									&memdb.StringFieldIndex{Field: "ControlPlaneHost"},
									&memdb.UUIDFieldIndex{Field: "ID"},
								},
							},
						},
						"control-plane-host": {
							Name:    "control-plane-host",
							Unique:  false,
							Indexer: &memdb.StringFieldIndex{Field: "ControlPlaneHost"},
						},
						"group": {
							Name:    "group",
							Unique:  false,
							Indexer: &StringPtrIndex{Field: "Group"},
						},
					},
				},
			},
		}

		// Create the in-memory database
		singleton.db, err = memdb.NewMemDB(schema)
	})

	if err != nil {
		return nil, fmt.Errorf("unable to create database: %w", err)
	}
	return singleton, nil
}

// DeleteNode deletes the configuration for the given host and node ID.
func (d *Database) DeleteNode(ctx context.Context, controlPlaneHost string, nodeID uuid.UUID) error {
	_, span := monitoring.Tracer.Start(ctx, "DeleteNode")
	defer span.End()

	txn := d.db.Txn(true)
	defer txn.Abort()
	p := Node{
		ControlPlaneHost: controlPlaneHost,
		ID:               nodeID.String(),
	}
	if err := txn.Delete("node", p); err != nil {
		return fmt.Errorf("unable to delete node for control plane host %s and node ID %v: %w",
			controlPlaneHost, nodeID, err)
	}
	txn.Commit()

	return nil
}

// / GetGroups returns a list of all groups for data plane nodes connected to
// control planes using the in-memory database.
func (d *Database) GetGroups(ctx context.Context) ([]string, error) {
	_, span := monitoring.Tracer.Start(ctx, "GetGroups")
	defer span.End()

	txn := d.db.Txn(false)
	defer txn.Abort()
	it, err := txn.Get("node", "group")
	if err != nil {
		return nil, fmt.Errorf("unable to get groups from database: %w", err)
	}

	groupSet := make(map[string]bool)
	groups := []string{}
	for obj := it.Next(); obj != nil; obj = it.Next() {
		n, ok := obj.(Node)
		if !ok {
			return nil, fmt.Errorf("unable to cast node for groups: %w", err)
		}
		if n.Group != nil {
			if _, exists := groupSet[*n.Group]; !exists {
				groupSet[*n.Group] = true
				groups = append(groups, *n.Group)
			}
		}
	}

	return groups, nil
}

// GetHosts returns a list of all hosts for data plane nodes connected to
// control planes using the in-memory database.
func (d *Database) GetHosts(ctx context.Context) ([]Hosts, error) {
	_, span := monitoring.Tracer.Start(ctx, "GetHosts")
	defer span.End()

	txn := d.db.Txn(false)
	defer txn.Abort()
	it, err := txn.Get("node", "control-plane-host")
	if err != nil {
		return nil, fmt.Errorf("unable to get control plane hosts from database: %w", err)
	}

	controlPlaneHostMap := make(map[string]map[string]bool)
	for obj := it.Next(); obj != nil; obj = it.Next() {
		n, ok := obj.(Node)
		if !ok {
			return nil, fmt.Errorf("unable to cast node for control plane hosts: %w", err)
		}

		if _, exists := controlPlaneHostMap[n.ControlPlaneHost]; !exists {
			controlPlaneHostMap[n.ControlPlaneHost] = make(map[string]bool)
		}
		if n.Group != nil {
			controlPlaneHostMap[n.ControlPlaneHost][*n.Group] = true
		}
	}

	hosts := []Hosts{}
	for controlPlaneHost, groups := range controlPlaneHostMap {
		var groupList []string
		for group := range groups {
			groupList = append(groupList, group)
		}
		hosts = append(hosts, Hosts{
			Hostname: controlPlaneHost,
			Groups:   groupList,
		})
	}

	return hosts, nil
}

// GetNodesByHost returns a list of all nodes connected to a control plane using
// the in-memory database.
func (d *Database) GetNodesByHost(ctx context.Context, controlPlaneHost string) ([]Node, error) {
	_, span := monitoring.Tracer.Start(ctx, "GetNodesByHost")
	defer span.End()

	txn := d.db.Txn(false)
	defer txn.Abort()
	it, err := txn.Get("node", "control-plane-host", controlPlaneHost)
	if err != nil {
		return nil, fmt.Errorf("unable to get nodes for control plane host %s from database: %w",
			controlPlaneHost, err)
	}

	nodes := []Node{}
	for obj := it.Next(); obj != nil; obj = it.Next() {
		p, ok := obj.(Node)
		if !ok {
			return nil, fmt.Errorf("unable to cast node for control plane host %s: %w",
				controlPlaneHost, err)
		}
		nodes = append(nodes, p)
	}
	if len(nodes) == 0 {
		return nil, ErrHostNotFound
	}

	return nodes, nil
}

// GetNodesByGroup returns a list of all nodes connected associated with a
// group using the in-memory database.
func (d *Database) GetNodesByGroup(ctx context.Context, group string) ([]Node, error) {
	_, span := monitoring.Tracer.Start(ctx, "GetNodesByGroup")
	defer span.End()

	txn := d.db.Txn(false)
	defer txn.Abort()
	it, err := txn.Get("node", "group", group)
	if err != nil {
		return nil, fmt.Errorf("unable to get nodes for group %s from database: %w", group, err)
	}

	nodes := []Node{}
	for obj := it.Next(); obj != nil; obj = it.Next() {
		p, ok := obj.(Node)
		if !ok {
			return nil, fmt.Errorf("unable to cast node for group %s: %w", group, err)
		}
		nodes = append(nodes, p)
	}
	if len(nodes) == 0 {
		return nil, ErrHostNotFound
	}

	return nodes, nil
}

// GetNode returns the node for the given host and node ID from the in-memory
// database.
func (d *Database) GetNode(ctx context.Context, host string, nodeID uuid.UUID) (*Node, error) {
	_, span := monitoring.Tracer.Start(ctx, "GetNode")
	defer span.End()

	txn := d.db.Txn(false)
	defer txn.Abort()
	raw, err := txn.First("node", "id", host, nodeID.String())
	if err != nil {
		return nil, fmt.Errorf("unable to get node for control plane host %s and node ID %v: %w", host, nodeID,
			err)
	}
	if raw == nil {
		return nil, ErrNodeNotFound
	}

	node, ok := raw.(Node)
	if !ok {
		return nil, fmt.Errorf("unable to cast node for control plane host %s and node ID %v: %w", host,
			nodeID, err)
	}
	return &node, nil
}

// SetNode sets the node for the given host and node ID in the in-memory
// database.
// Note: The entire node must be set and will overwrite any existing entry.
func (d *Database) SetNode(ctx context.Context, node Node) error {
	_, span := monitoring.Tracer.Start(ctx, "SetNode")
	defer span.End()

	txn := d.db.Txn(true)
	defer txn.Abort()
	if err := txn.Insert("node", node); err != nil {
		return fmt.Errorf("unable to insert node into database: %w", err)
	}
	txn.Commit()

	return nil
}
