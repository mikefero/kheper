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
	"testing"

	"github.com/mikefero/kheper/node"
	"github.com/stretchr/testify/require"
)

func TestProtocols(t *testing.T) {
	t.Run("verify standard protocol is parsed correctly", func(t *testing.T) {
		t.Parallel()

		p, err := node.Parse("standard")
		require.NoError(t, err)
		require.Equal(t, node.Standard, p)
	})

	t.Run("verify JSONRPC protocol is parsed correctly", func(t *testing.T) {
		t.Parallel()

		p, err := node.Parse("jsonrpc")
		require.NoError(t, err)
		require.Equal(t, node.JSONRPC, p)
	})

	t.Run("verify invalid protocol is not parsed", func(t *testing.T) {
		t.Parallel()

		p, err := node.Parse("invalid")
		require.ErrorContains(t, err, "invalid protocol")
		require.Equal(t, node.Standard, p)
	})
}
