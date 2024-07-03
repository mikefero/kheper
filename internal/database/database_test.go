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
package database_test

import (
	"testing"

	"github.com/google/uuid"
	"github.com/mikefero/kheper/internal/database"
	"github.com/stretchr/testify/require"
)

func TestDatabase(t *testing.T) {
	t.Run("verify database is created", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
	})

	t.Run("verify database is created only once", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		d2, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d2)
		require.Equal(t, d, d2)
	})

	t.Run("verify node is properly inserted into the database", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		id := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(expected)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", id)

		// Verify the node
		actual, err := d.GetNode("localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)
	})

	t.Run("verify node is properly updated in the database", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		id := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the Node
		err = d.SetNode(expected)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", id)

		// Verify the node
		actual, err := d.GetNode("localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)

		// Update the node
		payload = map[string]interface{}{"is_valid": false}
		expected.Payload = payload
		err = d.SetNode(expected)
		require.NoError(t, err)

		// Verify the updated node
		actual, err = d.GetNode("localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)
	})

	t.Run("verify multiple nodes are properly inserted into the database using the same host", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		node1ID := uuid.New()
		node2ID := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		expectedNode1 := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local.1",
			ID:               node1ID.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}
		expectedNode2 := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local.2",
			ID:               node2ID.String(),
			Payload:          payload,
			Version:          "1.2.3.1",
		}

		// Set the node
		err = d.SetNode(expectedNode1)
		require.NoError(t, err)
		err = d.SetNode(expectedNode2)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", node1ID)
		defer d.DeleteNode("localhost", node2ID)

		// Verify the nodes
		actual, err := d.GetNode("localhost", node1ID)
		require.NoError(t, err)
		require.Equal(t, &expectedNode1, actual)
		actual, err = d.GetNode("localhost", node2ID)
		require.NoError(t, err)
		require.Equal(t, &expectedNode2, actual)
	})

	t.Run("verify node is properly deleted from the database", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		id := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Verify the node is not found
		actual, err := d.GetNode("localhost", id)
		require.Equal(t, database.ErrNodeNotFound, err)
		require.Nil(t, actual)

		// Set the node
		err = d.SetNode(expected)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", id)

		// Verify the node
		actual, err = d.GetNode("localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)

		// Delete the node
		err = d.DeleteNode("localhost", id)
		require.NoError(t, err)

		// Verify the node is not found
		actual, err = d.GetNode("localhost", id)
		require.Equal(t, database.ErrNodeNotFound, err)
		require.Nil(t, actual)
	})

	t.Run("verify error occurs if host or node ID are not available when getting node", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		_, err = d.GetNode("localhost", uuid.New())
		require.Equal(t, database.ErrNodeNotFound, err)
	})

	t.Run("verify hosts are empty when no hosts are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		hosts, err := d.GetHosts()
		require.NoError(t, err)
		require.Len(t, hosts, 0)
	})

	t.Run("verify a single host is available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		payload := map[string]interface{}{"is_valid": true}
		id := uuid.New()
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(expected)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", id)

		// Verify the host
		hosts, err := d.GetHosts()
		require.NoError(t, err)
		require.Len(t, hosts, 1)
		require.Equal(t, "localhost", hosts[0])
	})

	t.Run("verify multiple hosts are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		node1ID := uuid.New()
		node2ID := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		err = d.SetNode(database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               node1ID.String(),
			Payload:          payload,
			Version:          "1.2.3",
		})
		require.NoError(t, err)
		err = d.SetNode(database.Node{
			ControlPlaneHost: "kheper.example.com",
			Hostname:         "kheper.local",
			ID:               node2ID.String(),
			Payload:          payload,
			Version:          "1.2.3.1",
		})
		require.NoError(t, err)
		defer d.DeleteNode("localhost", node1ID)
		defer d.DeleteNode("kheper.example.com", node2ID)

		hosts, err := d.GetHosts()
		require.NoError(t, err)
		require.Len(t, hosts, 2)
		require.ElementsMatch(t, []string{"localhost", "kheper.example.com"}, hosts)
	})

	t.Run("verify host is not found when no nodes are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		_, err = d.GetNodes("localhost")
		require.Equal(t, database.ErrHostNotFound, err)
	})

	t.Run("verify a single node is available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		payload := map[string]interface{}{"is_valid": true}
		id := uuid.New()
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(expected)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", id)

		// Verify the node
		nodes, err := d.GetNodes("localhost")
		require.NoError(t, err)
		require.Len(t, nodes, 1)
		require.Equal(t, expected, nodes[0])
	})

	t.Run("verify multiple nodes are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		node1ID := uuid.New()
		node2ID := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		expectedNode1 := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               node1ID.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}
		expectedNode2 := database.Node{
			ControlPlaneHost: "localhost",
			Hostname:         "kheper.local",
			ID:               node2ID.String(),
			Payload:          payload,
			Version:          "1.2.3.1",
		}

		// Set the node
		err = d.SetNode(expectedNode1)
		require.NoError(t, err)
		err = d.SetNode(expectedNode2)
		require.NoError(t, err)
		defer d.DeleteNode("localhost", node1ID)
		defer d.DeleteNode("localhost", node2ID)

		// Verify the nodes
		nodes, err := d.GetNodes("localhost")
		require.NoError(t, err)
		require.Len(t, nodes, 2)
		require.ElementsMatch(t, []database.Node{expectedNode1, expectedNode2}, nodes)
	})
}
