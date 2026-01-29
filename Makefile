.PHONY: peerinfo init-peerinfo node1 node2

# Profile configurations
ifneq ($(filter node1,$(MAKECMDGOALS)),)
PORT := 4001
NICKNAME := node1
DATA_DIR := .peerinfo-example_node1
METRICS_PORT := 9465
else ifneq ($(filter node2,$(MAKECMDGOALS)),)
PORT := 4002
NICKNAME := node2
DATA_DIR := .peerinfo-example_node2
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
		--loki-url http://localhost:3100 \
		--loki-label cluster=peerinfo-example \
		$(DIAL_ARGS)

# Initialize peerinfo by copying private key from cluster
# Usage: make init-peerinfo node1 CHARON_PATH=<path_to_charon>
init-peerinfo:
	mkdir -p $(DATA_DIR) && cp $(CHARON_PATH)/test-cluster/$(NICKNAME)/charon-enr-private-key $(DATA_DIR)

# No-op targets for profile selection
node1 node2:
	@:

# Catch-all for multiaddresses (prevents "No rule to make target" errors)
/%:
	@:
