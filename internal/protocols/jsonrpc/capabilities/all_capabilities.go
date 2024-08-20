package capabilities

import (
	"fmt"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/kong_debug/v1"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/kong_meta/v1"
	"golang.org/x/exp/maps"
)

// AllCapabilities is a map containing all implemented AllCapabilities
var AllCapabilities map[string]runtime.Wrapper

func Init() {
	// NOTE: add any new capability wrappers to this list.
	for _, w := range []runtime.Wrapper{
		kong_meta.Wrap(),
		kong_debug.Wrap(),
	} {
		AllCapabilities[w.GetID()] = w
	}
}

// KnownCapabilities returns the intersection between the given list of capability names
// and those implemented.
// If the given list is `nil`, it returns a list of all known capability names.
func KnownCapabilities(from []string) []string {
	if from == nil {
		return maps.Keys(AllCapabilities)
	}

	out := []string{}
	for _, k := range from {
		if _, found := AllCapabilities[k]; found {
			out = append(out, k)
		}
	}
	return out
}

// RegisterByName adds a capability to a connection.
func RegisterByName(conn *runtime.Conn, name string) error {
	capability, found := AllCapabilities[name]
	if !found {
		return fmt.Errorf("unknown capability name %q", name)
	}

	return conn.Register(capability)
}
