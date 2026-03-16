.PHONY: build dev register clean

PLUGIN_NAME := vault-plugin-auth-vims
PLUGIN_DIR  := vault/plugins

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" \
		-o bin/$(PLUGIN_NAME) ./cmd/$(PLUGIN_NAME)

# Start Vault dev server with the plugin directory, build, register, and enable.
dev: build
	@echo "=== Build complete: bin/$(PLUGIN_NAME) ==="
	@echo ""
	@echo "To use with a Vault dev server:"
	@echo ""
	@echo "  # Terminal 1: Start Vault"
	@echo "  vault server -dev -dev-root-token-id=root -dev-plugin-dir=./bin"
	@echo ""
	@echo "  # Terminal 2: Register & enable"
	@echo "  export VAULT_ADDR=http://127.0.0.1:8200"
	@echo "  export VAULT_TOKEN=root"
	@echo "  vault plugin register -sha256=\$$(sha256sum bin/$(PLUGIN_NAME) | cut -d' ' -f1) auth $(PLUGIN_NAME)"
	@echo "  vault auth enable -path=vims $(PLUGIN_NAME)"
	@echo ""
	@echo "  # Configure"
	@echo "  vault write auth/vims/config vims_addr=http://127.0.0.1:8169"
	@echo ""
	@echo "  # Create a role"
	@echo "  vault write auth/vims/role/web-tier \\"
	@echo "    bound_folder='/Production/Web/*' \\"
	@echo "    bound_tags=env=production,role=web \\"
	@echo "    token_policies=web-secrets-read \\"
	@echo "    token_ttl=1h"
	@echo ""
	@echo "  # Login (from a VM, or localhost in dev mode)"
	@echo "  vault write auth/vims/login role=web-tier"

clean:
	rm -rf bin/
