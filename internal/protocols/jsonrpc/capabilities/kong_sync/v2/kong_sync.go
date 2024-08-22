//go:generate go run github.com/Kong/go-openrpc/codegen/cmd/gen@latest -i kong.sync.yaml -o kong_sync.gen.go
package kong_sync

import (
	"context"

	"github.com/Kong/go-openrpc/runtime"
	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/store"
)

func Wrap() *Wrapper[store.MethodStore] {
	return &Wrapper[store.MethodStore]{
		Handler: syncHandler{},
	}
}

type syncHandler struct{}

func (h syncHandler) GetDelta(
	ctx context.Context,
	methodStore store.MethodStore,
	params *GetDeltaParams,
) (GetDeltaResponse, error) {
	if err := methodStore.RecordErrorResponse(params, runtime.MethodNotFoundError); err != nil {
		return nil, err
	}
	return nil, runtime.MethodNotFoundError
}

func (h syncHandler) NotifyNewVersion(
	ctx context.Context,
	methodStore store.MethodStore,
	params *NotifyNewVersionParams,
) (NotifyNewVersionResponse, error) {
	resp := NotifyNewVersionResult(true)
	if err := methodStore.RecordMethodCall(params, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
