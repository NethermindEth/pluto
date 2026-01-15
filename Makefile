.PHONY: peerinfo init-peerinfo node1 node2

# Profile configurations
ifneq ($(filter node1,$(MAKECMDGOALS)),)
PORT := 4001
NICKNAME := node1
DATA_DIR := .charon-example-peerinfo-1
METRICS_PORT := 9465
else ifneq ($(filter node2,$(MAKECMDGOALS)),)
PORT := 4002
NICKNAME := node2
DATA_DIR := .charon-example-peerinfo-2
METRICS_PORT := 9466
endif

# Extract dial addresses from command line (multiaddresses starting with /)
DIAL_ADDRS := $(filter /%,$(MAKECMDGOALS))

# Build the dial arguments
ifneq ($(DIAL_ADDRS),)
DIAL_ARGS := $(foreach addr,$(DIAL_ADDRS),--dial $(addr))
endif

# Run peerinfo with the selected profile
peerinfo:
	cargo run -p charon-peerinfo --example peerinfo -- \
		--port $(PORT) \
		--nickname $(NICKNAME) \
		--data-dir $(DATA_DIR) \
		--metrics-port $(METRICS_PORT) \
		$(DIAL_ARGS)

# Initialize peerinfo with a private key
# Usage: make init node1 KEY=<private_key>
init-peerinfo:
	cargo run -p charon-peerinfo --example peerinfo -- init \
		--data-dir $(DATA_DIR) \
		--private-key $(KEY)

# No-op targets for profile selection
node1 node2:
	@:

# Catch-all for multiaddresses (prevents "No rule to make target" errors)
/%:
	@:
