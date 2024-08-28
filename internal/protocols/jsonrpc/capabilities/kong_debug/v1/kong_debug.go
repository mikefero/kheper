//go:generate go run github.com/Kong/go-openrpc/codegen/cmd/gen@latest -i kong.debug.yaml -o kong_debug.gen.go
package kong_debug

import (
	"context"

	"github.com/mikefero/kheper/internal/protocols/jsonrpc/capabilities/store"
)

func Wrap() *Wrapper[store.MethodStore] {
	return &Wrapper[store.MethodStore]{
		Handler: debugHandler{},
	}
}

type debugHandler struct{}

func (dh debugHandler) GetLogLevel(ctx context.Context, methodStore store.MethodStore) (GetLogLevelResponse, error) {
	resp := GetLogLevelResult(0)
	if err := methodStore.RecordMethodCall(nil, resp); err != nil {
		return nil, err
	}

	return resp, nil
}

func (dh debugHandler) SetLogLevel(
	ctx context.Context,
	methodStore store.MethodStore,
	params *SetLogLevelParams,
) (SetLogLevelResponse, error,
) {
	resp := SetLogLevelResult(true)
	if err := methodStore.RecordMethodCall(params, resp); err != nil {
		return nil, err
	}
	return resp, nil
}
