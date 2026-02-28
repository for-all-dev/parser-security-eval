#!/bin/bash -eu
# Copyright 2022-2023 D. R. Commander
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################
#
# Adapted from https://github.com/google/oss-fuzz/tree/master/projects/libjpeg-turbo
# and https://github.com/libjpeg-turbo/libjpeg-turbo/blob/main/fuzz/build.sh
#
# Available environment variables (set by oss-fuzz base-builder):
#   $CC, $CXX           -- compiler (clang with sanitizer flags)
#   $CFLAGS, $CXXFLAGS  -- compiler flags (include sanitizer flags)
#   $LIB_FUZZING_ENGINE -- path to fuzzing engine library
#   $OUT                -- output directory for fuzz targets
#   $SRC                -- source directory (/src)
#   $WORK               -- working directory for build artifacts

# The oss-fuzz build.sh delegates to fuzz/build.sh in each branch directory.
# For our single-branch setup we run it directly from libjpeg-turbo.main.

build_branch() {
    local branch="$1"
    local suffix="${2:-}"
    local srcdir="$SRC/libjpeg-turbo.${branch}"

    pushd "$srcdir"

    if [ "$SANITIZER" = "memory" ]; then
        export CFLAGS="$CFLAGS -DZERO_BUFFERS=1"
    fi

    cmake . \
        -DCMAKE_BUILD_TYPE=RelWithDebInfo \
        -DENABLE_STATIC=1 \
        -DENABLE_SHARED=0 \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_CXX_COMPILER="$CXX" \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
        -DCMAKE_C_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
        -DCMAKE_CXX_FLAGS_RELWITHDEBINFO="-g -DNDEBUG" \
        -DCMAKE_INSTALL_PREFIX="$WORK" \
        -DWITH_FUZZ=1 \
        -DFUZZ_BINDIR="$OUT" \
        -DFUZZ_LIBRARY="$LIB_FUZZING_ENGINE" \
        -DFUZZER_SUFFIX="$suffix"

    make "-j$(nproc)" "--load-average=$(nproc)"
    make install

    # Attach seed corpora for compression fuzz targets
    for fuzzer in cjpeg \
                  compress \
                  compress_yuv \
                  compress_lossless \
                  compress12 \
                  compress12_lossless \
                  compress16_lossless; do
        cp "$SRC/compress_fuzzer_seed_corpus.zip" \
           "$OUT/${fuzzer}_fuzzer${suffix}_seed_corpus.zip"
    done

    # Attach seed corpora and dictionaries for decompression fuzz targets
    for fuzzer in libjpeg_turbo \
                  decompress_libjpeg \
                  decompress_yuv \
                  transform; do
        cp "$SRC/decompress_fuzzer_seed_corpus.zip" \
           "$OUT/${fuzzer}_fuzzer${suffix}_seed_corpus.zip"
        if [ -f "$srcdir/fuzz/jpeg.dict" ]; then
            cp "$srcdir/fuzz/jpeg.dict" \
               "$OUT/${fuzzer}_fuzzer${suffix}.dict"
        fi
    done

    popd
}

# Build the main branch (no suffix)
build_branch "main" ""
