# Requires the Ascend CANN/aarch64 toolchain; all artifacts are emitted to build/.
# Consensus / kernel configuration is fixed: rank=128, K=4096, 32 folds.
# There is no supported build-time rank or zero-fill mode switch.
MDIM ?= 16384
# Host strip slots (separate from kernel BUFS). Use 2 for an A/B baseline.
PIPE_DEPTH ?= 4

OUT  := build
# Locate BLAKE3 C sources from the Cargo registry when building the standalone miner.
BLK  ?= $(shell ls -d /root/.cargo/registry/src/*/blake3-1*/c 2>/dev/null | head -1)
BLK_SRC := $(BLK)/blake3.c $(BLK)/blake3_dispatch.c $(BLK)/blake3_portable.c $(BLK)/blake3_neon.c
CC   := gcc
# BLAKE3_USE_TBB uses the pthread split hook in blake3_join.c (not oneTBB).
CFLAGS := -std=gnu11 -O3 -fopenmp -march=armv8-a+crypto -DBLAKE3_USE_NEON=1 -DBLAKE3_USE_TBB -DMDIM=$(MDIM) -DPEARL_PIPE_DEPTH=$(PIPE_DEPTH) -I$(BLK)
RPATH  := -Wl,-rpath,'$$ORIGIN'

.PHONY: all miner kernel proof guard clean
all: kernel proof miner

$(OUT):
	mkdir -p $(OUT)

# Link exactly one frontend per binary; proof rank is fixed at 128.
ENGINE_SRC := src/miner.c src/proofgz.c src/pools/stratum.c src/prep.c src/scan_strip_async.c src/blake3_join.c src/cpu_budget.c $(BLK_SRC)
# Use libz's soname: some runtime images lack the libz.so development symlink.
LINK := -L$(OUT) -lpearl_hlc2 -lpearl_proof -lpthread -l:libz.so.1 $(RPATH)
miner: $(OUT)
	$(CC) $(CFLAGS) -o $(OUT)/ascend_prl_kryptex src/pools/kryptex.c $(ENGINE_SRC) $(LINK)
	$(CC) $(CFLAGS) -o $(OUT)/ascend_prl_k1       src/pools/k1.c      $(ENGINE_SRC) $(LINK)

# Optional guard requires the DCMI driver library and sufficient device privileges.
DCMI_DIR ?= /usr/local/dcmi
guard: $(OUT)
	$(CC) -O2 -I$(DCMI_DIR) -o $(OUT)/coexist_guard scripts/coexist_guard.c \
	    -L$(DCMI_DIR) -ldcmi -Wl,-rpath,$(DCMI_DIR)

kernel: $(OUT)
	cd kernel && rm -rf build && mkdir build && cd build && \
	  cmake -DCMAKE_ASC_RUN_MODE=npu -DCMAKE_ASC_ARCHITECTURES=dav-2201 \
	        -DPEARL_PIPE_DEPTH=$(PIPE_DEPTH) -DBUFS=4 -DVEC2X=2 \
	        -DCMAKE_MODULE_PATH="$$ASC_MODULES" .. && make -j
	cp kernel/build/libpearl_hlc2.so $(OUT)/

proof: $(OUT)
	cd proof-ffi && unset MAKEFLAGS && cargo build --release
	cp proof-ffi/target/release/libpearl_proof.so $(OUT)/

clean:
	rm -rf $(OUT) kernel/build proof-ffi/target
