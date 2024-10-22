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
	"context"
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
		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		actual, err := d.GetNode(context.TODO(), "localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)
	})

	t.Run("verify node is properly inserted into the database when group is nil", func(t *testing.T) {
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
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		actual, err := d.GetNode(context.TODO(), "localhost", id)
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
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		actual, err := d.GetNode(context.TODO(), "localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)

		// Update the node
		payload = map[string]interface{}{"is_valid": false}
		expected.Payload = payload
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)

		// Verify the updated node
		actual, err = d.GetNode(context.TODO(), "localhost", id)
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
		err = d.SetNode(context.TODO(), expectedNode1)
		require.NoError(t, err)
		err = d.SetNode(context.TODO(), expectedNode2)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", node1ID)
		defer d.DeleteNode(context.TODO(), "localhost", node2ID)

		// Verify the nodes
		actual, err := d.GetNode(context.TODO(), "localhost", node1ID)
		require.NoError(t, err)
		require.Equal(t, &expectedNode1, actual)
		actual, err = d.GetNode(context.TODO(), "localhost", node2ID)
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
		actual, err := d.GetNode(context.TODO(), "localhost", id)
		require.Equal(t, database.ErrNodeNotFound, err)
		require.Nil(t, actual)

		// Set the node
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		actual, err = d.GetNode(context.TODO(), "localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)

		// Delete the node
		err = d.DeleteNode(context.TODO(), "localhost", id)
		require.NoError(t, err)

		// Verify the node is not found
		actual, err = d.GetNode(context.TODO(), "localhost", id)
		require.Equal(t, database.ErrNodeNotFound, err)
		require.Nil(t, actual)
	})

	t.Run("verify error occurs if host or node ID are not available when getting node", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		_, err = d.GetNode(context.TODO(), "localhost", uuid.New())
		require.Equal(t, database.ErrNodeNotFound, err)
	})

	t.Run("verify hosts are empty when no hosts are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		hosts, err := d.GetHosts(context.TODO())
		require.NoError(t, err)
		require.Len(t, hosts, 0)
	})

	t.Run("verify a single host is available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		id := uuid.New()
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the host
		hosts, err := d.GetHosts(context.TODO())
		require.NoError(t, err)
		require.Len(t, hosts, 1)
		require.Equal(t, "localhost", hosts[0].Hostname)
		require.Len(t, hosts[0].Groups, 1)
		require.Equal(t, "test", hosts[0].Groups[0])
	})

	t.Run("verify multiple hosts are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		node1ID := uuid.New()
		group1 := "test-1"
		node2ID := uuid.New()
		payload := map[string]interface{}{"is_valid": true}
		err = d.SetNode(context.TODO(), database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group1,
			Hostname:         "kheper.local",
			ID:               node1ID.String(),
			Payload:          payload,
			Version:          "1.2.3",
		})
		require.NoError(t, err)
		err = d.SetNode(context.TODO(), database.Node{
			ControlPlaneHost: "kheper.example.com",
			Hostname:         "kheper.local",
			ID:               node2ID.String(),
			Payload:          payload,
			Version:          "1.2.3.1",
		})
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", node1ID)
		defer d.DeleteNode(context.TODO(), "kheper.example.com", node2ID)

		hosts, err := d.GetHosts(context.TODO())
		require.NoError(t, err)
		require.Len(t, hosts, 2)
		require.ElementsMatch(t, []database.Hosts{
			{
				Hostname: "localhost",
				Groups:   []string{"test-1"},
			},
			{
				Hostname: "kheper.example.com",
			},
		}, hosts)
	})

	t.Run("verify a single host is available when multiple nodes on the same host are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		node1ID := uuid.New()
		node2ID := uuid.New()
		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		err = d.SetNode(context.TODO(), database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               node1ID.String(),
			Payload:          payload,
			Version:          "1.2.3",
		})
		require.NoError(t, err)
		err = d.SetNode(context.TODO(), database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               node2ID.String(),
			Payload:          payload,
			Version:          "1.2.3.1",
		})
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", node1ID)
		defer d.DeleteNode(context.TODO(), "localhost", node2ID)

		hosts, err := d.GetHosts(context.TODO())
		require.NoError(t, err)
		require.Len(t, hosts, 1)
		require.Equal(t, "localhost", hosts[0].Hostname)
		require.Len(t, hosts[0].Groups, 1)
		require.Equal(t, group, hosts[0].Groups[0])
	})

	t.Run("verify host is not found when no nodes are available", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		_, err = d.GetNodesByHost(context.TODO(), "localhost")
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
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		nodes, err := d.GetNodesByHost(context.TODO(), "localhost")
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
		err = d.SetNode(context.TODO(), expectedNode1)
		require.NoError(t, err)
		err = d.SetNode(context.TODO(), expectedNode2)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", node1ID)
		defer d.DeleteNode(context.TODO(), "localhost", node2ID)

		// Verify the nodes
		nodes, err := d.GetNodesByHost(context.TODO(), "localhost")
		require.NoError(t, err)
		require.Len(t, nodes, 2)
		require.ElementsMatch(t, []database.Node{expectedNode1, expectedNode2}, nodes)
	})

	t.Run("verify node is properly inserted into the database", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		id := uuid.New()
		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		actual, err := d.GetNode(context.TODO(), "localhost", id)
		require.NoError(t, err)
		require.Equal(t, &expected, actual)
	})

	t.Run("verify nodes can be retrieved by group", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		id := uuid.New()
		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               id.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", id)

		// Verify the node
		actual, err := d.GetNodesByGroup(context.TODO(), group)
		require.NoError(t, err)
		require.Len(t, actual, 1)
		require.Equal(t, expected, actual[0])
	})

	t.Run("verify multiple nodes can be retrieved by group", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)
		nodeID1 := uuid.New()
		nodeID2 := uuid.New()
		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		expected := []database.Node{
			{
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               nodeID1.String(),
				Payload:          payload,
				Version:          "1.2.3",
			},
			{
				ControlPlaneHost: "localhost",
				Group:            &group,
				Hostname:         "kheper.local",
				ID:               nodeID2.String(),
				Payload:          payload,
				Version:          "1.2.3.1",
			},
		}

		// Set the nodes
		err = d.SetNode(context.TODO(), expected[0])
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", nodeID1)
		err = d.SetNode(context.TODO(), expected[1])
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", nodeID2)

		// Verify the node
		actual, err := d.GetNodesByGroup(context.TODO(), group)
		require.NoError(t, err)
		require.Len(t, actual, 2)
		require.ElementsMatch(t, expected, actual)
	})

	t.Run("verify no nodes are retrieved by group when group does not exist", func(t *testing.T) {
		d, err := database.NewDatabase()
		require.NoError(t, err)
		require.NotNil(t, d)

		// Attempt to retrieve invalid group when there are no nodes
		actual, err := d.GetNodesByGroup(context.TODO(), "invalid")
		require.Equal(t, database.ErrHostNotFound, err)
		require.Nil(t, actual)

		// Create a new node
		nodeID := uuid.New()
		group := "test"
		payload := map[string]interface{}{"is_valid": true}
		expected := database.Node{
			ControlPlaneHost: "localhost",
			Group:            &group,
			Hostname:         "kheper.local",
			ID:               nodeID.String(),
			Payload:          payload,
			Version:          "1.2.3",
		}

		// Set the node
		err = d.SetNode(context.TODO(), expected)
		require.NoError(t, err)
		defer d.DeleteNode(context.TODO(), "localhost", nodeID)

		// Attempt to retrieve invalid group
		actual, err = d.GetNodesByGroup(context.TODO(), "invalid")
		require.Equal(t, database.ErrHostNotFound, err)
		require.Nil(t, actual)
	})
}
