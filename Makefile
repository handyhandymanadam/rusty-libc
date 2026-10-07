export CARGO_BUILD_JOBS ?= 4
CARGO := cargo +nightly
SYSROOT := $(CURDIR)/target/sysroot
STD := -Zbuild-std=core,compiler_builtins

.PHONY: all sysroot shared clean
all: sysroot

sysroot:
	RUSTFLAGS="-C relocation-model=static -C llvm-args=-align-all-functions=6" $(CARGO) build --profile rt $(STD) --target x86_64-unknown-linux-gnu \
		-p rusty-libc-cabi --features runtime --target-dir target/rt
	mkdir -p $(SYSROOT)/lib $(SYSROOT)/include
	cp target/rt/x86_64-unknown-linux-gnu/rt/librusty_libc_cabi.a $(SYSROOT)/lib/libc.a
	@if nm $(SYSROOT)/lib/libc.a 2>/dev/null | grep -q _mm_fmadd_sd; then echo "ERROR: out-of-line _mm_fmadd_sd in libc.a"; exit 1; fi
	tools/weaken-libc.sh $(SYSROOT)/lib/libc.a
	rustc +nightly --edition 2021 --crate-type lib --emit obj -C panic=abort -C relocation-model=static -C opt-level=2 \
		--target x86_64-unknown-linux-gnu -o $(SYSROOT)/lib/crt1.o crates/rusty-libc-cabi/crt/crt1.rs
	for o in crti crtn; do rustc +nightly --edition 2021 --crate-type lib --emit obj -C panic=abort -C relocation-model=static -C opt-level=2 \
		--target x86_64-unknown-linux-gnu -o $(SYSROOT)/lib/$$o.o crates/rusty-libc-cabi/crt/$$o.rs; done
	rm -f $(SYSROOT)/lib/libm.a && ar crs $(SYSROOT)/lib/libm.a
	python3 tools/gen_headers.py $(SYSROOT)/include

shared:
	tools/build-shared.sh

clean:
	rm -rf target
