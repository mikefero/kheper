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
package node

import (
	"errors"
	"strings"
)

// Protocol is the protocol to use to communicate with the control plane.
type Protocol int

const (
	// Standard is the standard protocol.
	Standard Protocol = iota
	// JSONRPC is the JSON RPC protocol.
	JSONRPC
)

// String returns the string representation of the protocol.
func (p Protocol) String() string {
	return [...]string{"Standard", "JSONRPC"}[p]
}

// Parse parses the string representation of the protocol.
func Parse(s string) (Protocol, error) {
	switch strings.ToLower(s) {
	case "standard":
		return Standard, nil
	case "jsonrpc":
		return JSONRPC, nil
	default:
		return 0, errors.New("invalid protocol")
	}
}
