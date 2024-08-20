//go:generate go run github.com/Kong/go-openrpc/codegen/cmd/gen@latest -i kong.debug.yaml -o kong_debug.gen.go
package kong_debug

import "context"

type node interface {
	GetLogLevel() int
	SetLogLevel(int)
}

func Wrap() *Wrapper[node] {
	return &Wrapper[node]{
		Handler: debugHandler{},
	}
}

type debugHandler struct{}

func (dh debugHandler) GetLogLevel(ctx context.Context, node node) (GetLogLevelResponse, error) {
	return GetLogLevelResult(node.GetLogLevel()), nil
}

func (dh debugHandler) SetLogLevel(
	ctx context.Context,
	node node,
	params *SetLogLevelParams,
) (SetLogLevelResponse, error,
) {
	node.SetLogLevel(int(params.LogLevel))
	return SetLogLevelResult(true), nil
}
