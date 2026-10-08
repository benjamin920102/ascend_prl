# Requires the Ascend CANN/aarch64 toolchain; all artifacts are emitted to build/.
# RANK selects compatible K, NINNER, and NFOLD combinations.

RANK ?= 128
ifeq ($(RANK),512)
  K := 8192
  NINNER := 4
  NFOLD  := 16
else ifeq ($(RANK),256)
  # k=4096 is the ONLY legal k at r=256 (16r=4096<=k<=4r^2, pool cap k<=4096). AI=r/8=32,
  # the max reachable under a k<=4096 pool. MM_K=NINNER*128=256 (half the 512 L0B-fill).
  K := 4096
  NINNER := 2
  NFOLD  := 16
else ifeq ($(RANK),128)
  K := 4096
  NINNER := 1
  NFOLD  := 32
else ifeq ($(RANK),1024)
  K := 16384
  NINNER := 8
  NFOLD  := 16
else
  $(error RANK must be 128, 256, 512, or 1024)
endif
MDIM ?= 16384

OUT  := build
# Locate BLAKE3 C sources from the Cargo registry when building the standalone miner.
BLK  ?= $(shell ls -d /root/.cargo/registry/src/*/blake3-1*/c 2>/dev/null | head -1)
BLK_SRC := $(BLK)/blake3.c $(BLK)/blake3_dispatch.c $(BLK)/blake3_portable.c $(BLK)/blake3_neon.c
CC   := gcc
# BLAKE3_USE_TBB uses the pthread split hook in blake3_join.c (not oneTBB).
# DEV_FEE_PERMILLE=0 disables the developer time slice.
DEV_FEE_PERMILLE ?= 10
CFLAGS := -O3 -fopenmp -march=armv8-a+crypto -DBLAKE3_USE_NEON=1 -DBLAKE3_USE_TBB -DK=$(K) -DRANK=$(RANK) -DMDIM=$(MDIM) -DDEV_FEE_PERMILLE=$(DEV_FEE_PERMILLE) -I$(BLK)
RPATH  := -Wl,-rpath,'$$ORIGIN'
MBATCH ?= 1

.PHONY: all miner kernel proof guard clean
all: kernel proof miner

$(OUT):
	mkdir -p $(OUT)

# Link exactly one frontend per binary; build-time rank/shape is encoded in the proof.
ENGINE_SRC := src/miner.c src/proofgz.c src/pools/stratum.c src/prep.c src/scan_mbatch_async.c src/blake3_join.c $(BLK_SRC)
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
	        -DNINNER=$(NINNER) -DNFOLD=$(NFOLD) -DBUFS=4 -DVEC2X=2 -DMBATCH=$(MBATCH) \
	        -DCMAKE_MODULE_PATH="$$ASC_MODULES" .. && make -j
	cp kernel/build/libpearl_hlc2.so $(OUT)/

proof: $(OUT)
	cd proof-ffi && unset MAKEFLAGS && cargo build --release
	cp proof-ffi/target/release/libpearl_proof.so $(OUT)/

clean:
	rm -rf $(OUT) kernel/build proof-ffi/target
