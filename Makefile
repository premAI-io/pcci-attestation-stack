.PHONY: nvidia-cpp-sdk bins wasm

nvidia-cpp-sdk:
	git clone \
		-b main \
		--depth 1 \
		https://github.com/coval3nte/attestation-sdk \
		attestation-sdk || true \
	&& cd attestation-sdk \
	&& git fetch --depth 1 origin 1f54b2d4041d59e77004437e550bc8be474d7d9c \
	&& git checkout 1f54b2d4041d59e77004437e550bc8be474d7d9c \
	&& cd nv-attestation-sdk-cpp \
	&& cmake -S . -B build \
		-DCMAKE_TOOLCHAIN_FILE=$(CURDIR)/toolchain-x86_64-linux-gnu.cmake \
		-DCMAKE_INSTALL_PREFIX=$${SYSROOT:-/usr/local} \
	&& cmake --build build -j$(nproc) \
	&& sudo cmake --install build --strip \
	&& sudo ldconfig

bins:
	cargo build --target x86_64-unknown-linux-gnu --release

wasm:
	wasm-pack build --scope premai-io prem-rs

clean:
	rm -rf \
		attestation-sdk \
		target