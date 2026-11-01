# Build the runtime into a private sysroot and run the C and Rust test programs.
# Never touches the system libc: everything lands under target/sysroot.
export RUSTUP_HOME := $(HOME)/.rustup-libc
export CARGO_BUILD_JOBS ?= 4
# Heavy jobs run in a memory-capped scope so a runaway build cannot push the laptop into OOM.
# at most two heavy jobs at once (tools/heavy), whichever session or helper starts them
LIMIT := $(CURDIR)/tools/heavy
CARGO := $(LIMIT) cargo +nightly
SYSROOT := $(CURDIR)/target/sysroot
STD := -Zbuild-std=core,compiler_builtins
# test and benchmark programs: tests/testcc (clang by default, TEST_CC=gcc for the second check; GNU ld for every link)
export TEST_CC ?= clang
TESTCC := $(CURDIR)/tests/testcc
CCINC := $(shell $(TESTCC) --include)

.PHONY: all guard check sysroot test bench bench-math bench-mathcl bench-malloc bench-stdio bench-ctype bench-cover bench-locale symbols clean
all: sysroot

# Refuse to start a build when less than 3 GB of memory is available.
guard:
	@avail=$$(awk '/MemAvailable/{print int($$2/1024)}' /proc/meminfo); \
	 if [ $$avail -lt 3000 ]; then echo "only $$avail MB available; not starting a build"; exit 1; fi

# The project gates on host (nightly: C variadic definitions need Rust 1.99+, which stable has not shipped yet).
check: guard
	$(LIMIT) nice -n 10 cargo +nightly build --workspace
	$(LIMIT) nice -n 10 cargo +nightly test --workspace --release
	$(LIMIT) nice -n 10 cargo +nightly clippy --workspace --tests -- -D warnings
	tools/clippy-ldso.sh
	tools/clippy-hdrgen.sh

sysroot: guard
	RUSTFLAGS="-C relocation-model=static -C llvm-args=-align-all-functions=6" $(CARGO) build --profile rt $(STD) --target x86_64-unknown-linux-gnu \
		-p rusty-libc-cabi --features runtime --target-dir target/rt
	mkdir -p $(SYSROOT)/lib $(SYSROOT)/include
	cp target/rt/x86_64-unknown-linux-gnu/rt/librusty_libc_cabi.a $(SYSROOT)/lib/libc.a
	# libm kernels using `fma_i` (the fma intrinsic) must be inlined into `fma` functions: an out-of-line intrinsic is a call per operation
	@if nm $(SYSROOT)/lib/libc.a 2>/dev/null | grep -q _mm_fmadd_sd; then echo "ERROR: out-of-line _mm_fmadd_sd in libc.a (fma_i used outside a target_feature(fma) function)"; exit 1; fi
	# all definitions weak: a program's own function with a libc name must win, not clash (see the script)
	tools/weaken-libc.sh $(SYSROOT)/lib/libc.a
	# crt1.o: first object on the link line, makes `main` undefined before the archives are scanned
	rustc +nightly --edition 2021 --crate-type lib --emit obj -C panic=abort -C relocation-model=static -C opt-level=2 \
		--target x86_64-unknown-linux-gnu -o $(SYSROOT)/lib/crt1.o crates/rusty-libc-cabi/crt/crt1.rs
	for o in crti crtn; do rustc +nightly --edition 2021 --crate-type lib --emit obj -C panic=abort -C relocation-model=static -C opt-level=2 \
		--target x86_64-unknown-linux-gnu -o $(SYSROOT)/lib/$$o.o crates/rusty-libc-cabi/crt/$$o.rs; done
	# the math functions live in libc.a; an empty libm.a makes -lm work
	rm -f $(SYSROOT)/lib/libm.a && ar crs $(SYSROOT)/lib/libm.a
	# the C headers: built by tools/hdrgen (Rust) from the library crates and from header data held in Rust files
	$(CARGO) build --release --manifest-path tools/hdrgen/Cargo.toml --target-dir target/hdrgen
	target/hdrgen/release/hdrgen headers --root $(CURDIR) --out $(SYSROOT)/include --tests-out $(CURDIR)/target/tests-include

test: sysroot
	tests/run.sh

# Real programs nobody on this project wrote (lua, zlib, sqlite, GNU make, busybox, coreutils, bash, rusty-coreutils), built
# static against the sysroot; each tests/real/<name>.sh downloads its pinned source into ~/Claude/libc-upstream/real, builds in
# ~/Claude/tmp/real and runs the program's own test suite. Slow (about 40 minutes in all); PROGRAMS="lua zlib" picks some.
PROGRAMS ?= lua zlib sqlite make busybox coreutils bash rusty-coreutils
real-test: sysroot
	rc=0; for p in $(PROGRAMS); do echo "== $$p"; tests/real/$$p.sh || rc=1; done; exit $$rc

# Each benchmark is built at four code layouts so that a lucky or unlucky placement does not decide the result; the
# comparison takes the median ratio over the layouts. PAD bytes of padding go at the start of the bench program's .text,
# which the linker places before the libc members, so everything after it moves. Our libc.a is built with every function
# 64-byte aligned (-align-all-functions=6), so a pad below 64 bytes leaves its layout as it was (pads 16, 32 and 48 gave
# identical addresses); each pad here is 64*k + 16*j: the 64*k part moves our functions within the 4 KiB page (cache sets,
# branch predictor and uop cache indexes, page crossings), the 16*j part still varies glibc's 16-byte aligned code.
PADS := 0 1104 2528 3952
# Each code layout is also built at four data offsets (bench/dpad.c, FIXLIST #129): DPAD bytes go between the bench
# program's data and libc's, so libc's .data, the .bss and the heap move by DPAD. memcmp/bcmp-style cells swing by up to
# 30% with buffer alignment alone; the four offsets cover each 16-byte class modulo 64 (and four places in the page), so
# a change that only moves libc's data by a multiple of 16 bytes permutes the layouts and leaves the median as it was.
# 16 layouts in all, ROUNDS alternating glibc/ours runs at each (2 by default: the floor is the minimum over the rounds,
# and with a single round one run that comes out slow as a whole, as happens on a busy machine, decides its layout).
DPADS := 0 1040 2080 3120
# Relative placement (FIXLIST #115 follow-up, note c): the code pads move all of our code together (every function stays
# 64-byte aligned), so they never move one function against another, yet a 0x140-byte shift of identical code moved a
# strftime cell by 4%. ORDERS placement orders of our functions: order 0 is the linker's default, order k > 0 links ours with
# target/bench/order-k.ld (tools/bench_order.py: the archive's order with pads of 0..7 x 64 bytes between groups of 16
# sections, chosen per k by a hash of the section names). The orders are spread over the 16 code x data layouts as a Latin
# square (layout (code pad i, data pad j) gets order (i + j) mod ORDERS: every code pad and every data pad meets every
# order), so the layouts now sample relative placement too and a run takes as long as before. A layout is named
# <code pad>d<data pad>o<order>. glibc's side is linked as before (no order file).
ORDERS := 4
LAYOUTS := $(shell pi=0; for p in $(PADS); do di=0; for d in $(DPADS); do printf '%sd%so%s ' $$p $$d $$(( (pi + di) % $(ORDERS) )); di=$$((di + 1)); done; pi=$$((pi + 1)); done)
# Shell loop over the layouts for the bench recipes: writes the order files from our libc.a, then sets p (code pad), d (data
# pad), l (layout name) and ORD (the link option of our side) for each layout.
LAYOUT_LOOP = tools/bench_order.py $(SYSROOT)/lib/libc.a target/bench $$(($(ORDERS) - 1)) && for l in $(LAYOUTS); do \
	set -- $$(echo $$l | tr do '  '); p=$$1; d=$$2; ORD=; [ $$3 = 0 ] || ORD=-Wl,--section-ordering-file=target/bench/order-$$3.ld;
ROUNDS ?= 2
CPU ?= 3
ONLY ?=
bench: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/bench-glibc-pad$$l bench/bench.c bench/dpad.c; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/bench-ours-pad$$l bench/bench.c bench/dpad.c $(SYSROOT)/lib/libc.a; \
	done
	tools/bench_compare.py --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

# libm: C-call benchmarks at the code x data layouts (tests/c/math_bench.c: double/float, math_bench_cl.c: long double and complex)
bench-math: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/math-glibc-pad$$l tests/c/math_bench.c bench/dpad.c -lm; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/math-ours-pad$$l tests/c/math_bench.c bench/dpad.c $(SYSROOT)/lib/libc.a -lgcc; \
	done
	tools/bench_compare.py --stem=math --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

bench-mathcl: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/mathcl-glibc-pad$$l tests/c/math_bench_cl.c bench/dpad.c -lm; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/mathcl-ours-pad$$l tests/c/math_bench_cl.c bench/dpad.c $(SYSROOT)/lib/libc.a -lgcc; \
	done
	tools/bench_compare.py --stem=mathcl --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

bench-malloc: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/mbench-glibc-pad$$l bench/malloc_bench.c bench/dpad.c; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/mbench-ours-pad$$l bench/malloc_bench.c bench/dpad.c $(SYSROOT)/lib/libc.a; \
	done
	tools/bench_compare.py --stem=mbench --layouts="$(LAYOUTS)" --all --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

bench-stdio: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/sbench-glibc-pad$$l bench/stdio_bench.c bench/dpad.c; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/sbench-ours-pad$$l bench/stdio_bench.c bench/dpad.c $(SYSROOT)/lib/libc.a; \
	done
	tools/bench_compare.py --stem=sbench --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

bench-ctype: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/cbench-glibc-pad$$l bench/ctype_bench.c bench/dpad.c; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/cbench-ours-pad$$l bench/ctype_bench.c bench/dpad.c $(SYSROOT)/lib/libc.a; \
	done
	tools/bench_compare.py --stem=cbench --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

bench-cover: sysroot
	mkdir -p target/bench
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/covbench-glibc-pad$$l bench/cover_bench.c bench/dpad.c; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/covbench-ours-pad$$l bench/cover_bench.c bench/dpad.c $(SYSROOT)/lib/libc.a; \
	done
	tools/bench_compare.py --stem=covbench --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

# setlocale/newlocale/uselocale with 2 locales loaded and with every installed locale loaded (FIXLIST #122)
bench-locale: sysroot
	mkdir -p target/bench
	locale -a > target/bench/locale-names.txt
	$(LAYOUT_LOOP) \
		$(TESTCC) -O2 -fno-builtin -static -DPAD=$$p -DDPAD=$$d -o target/bench/locbench-glibc-pad$$l bench/locale_bench.c bench/dpad.c; \
		$(TESTCC) -O2 -fno-builtin -static -nostdlib -nostdinc -DPAD=$$p -DDPAD=$$d $$ORD -isystem $(SYSROOT)/include -isystem $(CCINC) \
			-o target/bench/locbench-ours-pad$$l bench/locale_bench.c bench/dpad.c $(SYSROOT)/lib/libc.a; \
	done
	tools/bench_compare.py --stem=locbench --layouts="$(LAYOUTS)" --rounds=$(ROUNDS) --cpu=$(CPU) $(if $(ONLY),--only=$(ONLY)) $(BENCHX)

symbols: sysroot
	tools/gen_symbols.py

clean:
	rm -rf target
