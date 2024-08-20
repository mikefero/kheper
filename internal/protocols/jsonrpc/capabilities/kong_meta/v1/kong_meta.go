//go:generate go run github.com/Kong/go-openrpc/codegen/cmd/gen@latest -i kong.meta.yaml -o kong_meta.gen.go
package kong_meta

import (
	"context"

	"github.com/Kong/go-openrpc/runtime"
)

type node interface{}

func Wrap() *Wrapper[node] {
	return &Wrapper[node]{
		Handler: metaHandler{},
	}
}

type metaHandler struct {
}

func (mh metaHandler) CapabilityAdvertisement(
	ctx context.Context,
	node node,
	params *CapabilityAdvertisementParams,
) (CapabilityAdvertisementResponse, error) {
	return nil, runtime.MethodNotFoundError
}
