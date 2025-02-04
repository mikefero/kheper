# --------------------------------------------------
# Test tooling
# --------------------------------------------------

# Ensure go is available
ifeq (, $(shell which go 2> /dev/null))
$(error "'go' is not installed or available in PATH")
endif

# Determine the packages for coverage ignoring generated code
COVERAGE_PACKAGES=$(shell go list ./... | grep -v "internal/api")

.PHONY: test
test:
	@go test -race ./...

.PHONY: test-coverage
test-coverage:
	@go test -race -coverprofile=$(APP_DIR)/coverage.out -covermode=atomic $(shell echo $(COVERAGE_PACKAGES) | tr '\n' ' ')
	@go tool cover -html=$(APP_DIR)/coverage.out -o $(APP_DIR)/coverage.html

.PHONY: test-no-cache
test-no-cache:
	@go test -count=1 -race ./...

.PHONY: test-no-race
test-no-race:
	@go test ./...

.PHONY: test-no-cache-no-race
test-no-cache-no-race:
	@go test -count=1 ./...
