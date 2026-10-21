LND_VERSION ?= v0.18.5-beta
LND_REPO_RAW_URL := https://raw.githubusercontent.com/lightningnetwork/lnd/$(LND_VERSION)/lnrpc
VENDOR_DIR := vendor
PROTO_DIRS := invoicesrpc peersrpc routerrpc signrpc verrpc walletrpc

ROOT_PROTOS := lightning.proto

PROTO_NAMES := invoicesrpc/invoices.proto peersrpc/peers.proto routerrpc/router.proto signrpc/signer.proto verrpc/verrpc.proto walletrpc/walletkit.proto
SUB_PROTOS := $(addprefix $(VENDOR_DIR)/, $(PROTO_NAMES))

TARGET_PROTOS := $(addprefix $(VENDOR_DIR)/, $(ROOT_PROTOS)) $(SUB_PROTOS)

.PHONY: all clean fetch-protos

all: fetch-protos

fetch-protos: $(TARGET_PROTOS)

ROOT_PROTO_TARGETS := $(addprefix $(VENDOR_DIR)/, $(ROOT_PROTOS))

$(ROOT_PROTO_TARGETS):
	@echo "Fetching $(@) from lnrpc/..."
	@mkdir -p $(VENDOR_DIR)
	@curl -sSfL -o $@ "$(LND_REPO_RAW_URL)/$(@F)"


define SUBDIR_RULE_TEMPLATE
$(VENDOR_DIR)/$(1)/%.proto:
	@echo "Fetching $$@ from lnrpc/$(1)/..."
	@mkdir -p $$(@D)
	@curl -sSfL -o $$@ "$(LND_REPO_RAW_URL)/$(1)/$$(@F)"
endef

$(foreach dir,$(PROTO_DIRS),$(eval $(call SUBDIR_RULE_TEMPLATE,$(dir))))

clean:
	@echo "Cleaning vendor directory..."
	@rm -rf $(VENDOR_DIR)

# Example usage:
# make fetch-protos LND_VERSION=v0.17.0-beta
# make clean 
