#!/bin/bash
# Build kernel, Rust proof FFI, and miner inside the CANN 9.0.0 container.
set -e
RANK="${RANK:-128}"
source /usr/local/Ascend/cann-9.0.0/set_env.sh
export ASC_MODULES=/usr/local/Ascend/cann-9.0.0/aarch64-linux/tikcpp/ascendc_kernel_cmake/asc_modules

# container clock skews ~200s vs the host; touch so make/cmake don't see future mtimes
find . -type f -exec touch {} +

make RANK="$RANK" kernel
make RANK="$RANK" proof
make RANK="$RANK" miner

echo "=== built (RANK=$RANK) ==="
ls -la build/
