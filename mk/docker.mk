# --------------------------------------------------
# Docker tooling
# --------------------------------------------------

# Ensure docker compose is available
ifeq (, $(shell which docker compose 2> /dev/null))
	$(error "'docker compose' is not installed or available in PATH")
endif

.PHONY: kong-down
kong-down:
	@docker compose -f "$(APP_DIR)/docker/kong/docker-compose.yml" down

.PHONY: kong-up
kong-up:
	@docker compose -f "$(APP_DIR)/docker/kong/docker-compose.yml" up -d

.PHONY: kong-up-stdout
kong-up-stdout:
	@docker compose -f "$(APP_DIR)/docker/kong/docker-compose.yml" up
