CARGO_CMD := cargo build
TARGET := x86_64-unknown-linux-gnu
FEATURES := hyperv
RELEASE_FLAG := -r

bins-hyperv:
	$(CARGO_CMD) $(RELEASE_FLAG) \
		--features $(FEATURES) \
		--target $(TARGET) \
		--bins

verifier-hyperv:
	$(CARGO_CMD) $(RELEASE_FLAG) \
		--features $(FEATURES) \
		--target $(TARGET)

pcr-hyperv:
	$(CARGO_CMD) $(RELEASE_FLAG) \
		--features $(FEATURES) \
		--target $(TARGET) \
		--bin pcr

fmt:
	cargo fmt
