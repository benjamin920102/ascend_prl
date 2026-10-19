cmake_minimum_required(VERSION 3.16)
set(CMAKE_ASC_ARCHITECTURES "dav-2201" CACHE STRING "NPU architecture")
find_package(ASC REQUIRED)
project(pearl_hlc2 LANGUAGES ASC CXX)
# Tuned config: NINNER=1 NFOLD=32 BUFS=4 VEC2X=2
set(PEARL_BAND_GROUP "2" CACHE STRING "adjacent bands per Matmul")
set(NINNER "1"  CACHE STRING "inner matmuls per fold-step")
set(NFOLD  "32" CACHE STRING "fold-steps")
set(PEARL_PIPE_DEPTH "4" CACHE STRING "host strip queue depth")
set(BUFS "4" CACHE STRING "slot ping-pong depth")
set(BACKOFF "500" CACHE STRING "spin backoff iters")
set(VEC2X "2" CACHE STRING "vec consumers per cube producer")
add_library(pearl_hlc2 SHARED pearl_hlc2_cube.asc pearl_hlc2_vec.asc)
set_target_properties(pearl_hlc2 PROPERTIES POSITION_INDEPENDENT_CODE ON)
target_link_libraries(pearl_hlc2 PRIVATE tiling_api register platform m dl pthread)
target_compile_options(pearl_hlc2 PRIVATE
    $<$<COMPILE_LANGUAGE:ASC>:--npu-arch=${CMAKE_ASC_ARCHITECTURES}>
    $<$<COMPILE_LANGUAGE:ASC>:-DPEARL_BAND_GROUP=${PEARL_BAND_GROUP}>
    $<$<COMPILE_LANGUAGE:ASC>:-DNINNER=${NINNER}>
    $<$<COMPILE_LANGUAGE:ASC>:-DNFOLD=${NFOLD}>
    $<$<COMPILE_LANGUAGE:ASC>:-DPEARL_PIPE_DEPTH=${PEARL_PIPE_DEPTH}>
    $<$<COMPILE_LANGUAGE:ASC>:-DBUFS=${BUFS}>
    $<$<COMPILE_LANGUAGE:ASC>:-DBACKOFF=${BACKOFF}>
    $<$<COMPILE_LANGUAGE:ASC>:-DVEC2X=${VEC2X}>
)
