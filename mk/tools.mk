# --------------------------------------------------
# Tools tooling
# --------------------------------------------------

GOLANGCI_LINT_VERSION ?= v1.59.1
OAPI_CODEGEN_CLI_VERSION ?= v2.3.0

GOFILES := $(shell find $(APP_DIR) -name '*.go' ! -name '*_test.go')

# Ensure curl, docker gofumpt are available
ifeq (, $(shell which curl 2> /dev/null))
$(error "'curl' is not installed or available in PATH")
endif
ifeq (, $(shell which docker 2> /dev/null))
$(error "'docker' is not installed or available in PATH")
endif
ifeq (, $(shell which gofumpt 2> /dev/null))
$(error "'gofumpt' is not installed or available in PATH")
endif

.PHONY: install-tools
install-tools:
	@GOBIN="$(APP_DIR)/bin" go install github.com/oapi-codegen/oapi-codegen/v2/cmd/oapi-codegen@$(OAPI_CODEGEN_CLI_VERSION)
	@curl -sSfL \
		"https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh" \
		| sh -s -- -b "$(APP_DIR)/bin" "$(GOLANGCI_LINT_VERSION)"

.PHONY: lint-oas
lint-oas:
	@docker run --rm -it \
		-v "$(APP_DIR)/openapi.yml:/spec/openapi.yml" \
		-v "$(APP_DIR)/redocly.yml:/spec/redocly.yml" \
		redocly/cli lint \
			--config /spec/redocly.yml \
			/spec/openapi.yml

.PHONY: lint
lint: lint-oas
	@"$(APP_DIR)/bin/golangci-lint" run ./...

.PHONY: format
format:
	@gofumpt -w $(GOFILES)

