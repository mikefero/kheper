//go:generate go run github.com/Kong/go-openrpc/codegen/cmd/gen@latest -i kong.meta.yaml -o kong_meta.gen.go
package kong_meta

import (
	"context"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/store"
)

func Wrap() *Wrapper[store.MethodStore] {
	return &Wrapper[store.MethodStore]{
		Handler: metaHandler{},
	}
}

type metaHandler struct {
}

func (mh metaHandler) CapabilityAdvertisement(
	ctx context.Context,
	methodStore store.MethodStore,
	params *CapabilityAdvertisementParams,
) (CapabilityAdvertisementResponse, error) {
	if err := methodStore.RecordErrorResponse(runtime.MethodNotFoundError); err != nil {
		return nil, err
	}

	return nil, runtime.MethodNotFoundError
}
