package capabilities

import (
	"fmt"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/kong_debug/v1"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/kong_meta/v1"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/kong_sync/v2"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/store"
	"golang.org/x/exp/maps"
)

type compatibleWrapper interface {
	runtime.Wrapper
	SetUserData(*runtime.Conn, store.MethodStore)
}

// AllCapabilities is a map containing all implemented capabilities
// NOTE: add here any new capability as they're implemented
var AllCapabilities = makeWrapperMap(
	kong_meta.Wrap(),
	kong_debug.Wrap(),
	kong_sync.Wrap(),
)

func makeWrapperMap(wrappers ...compatibleWrapper) map[string]compatibleWrapper {
	// m := map[string]compatibleWrapper{}
	m := make(map[string]compatibleWrapper, len(wrappers))
	for _, w := range wrappers {
		m[w.GetID()] = w
	}
	return m
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
	capability, found_that := AllCapabilities[name]
	if !found_that {
		return fmt.Errorf("unknown capability name %q", name)
	}

	return conn.Register(capability)
}
