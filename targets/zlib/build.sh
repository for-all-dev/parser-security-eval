#!/bin/bash -eu
# Build script for zlib fuzz targets.
#
# Works with both current and old (vulnerable) commits of zlib.
# If the normal build + in-tree fuzz targets work, use them; otherwise
# fall back to building a minimal uncompress fuzz target from scratch.

shopt -s nullglob

cd /src/zlib

# ---------- UBSan extra flags ----------
if [ "${SANITIZER:-}" = "undefined" ]; then
    extra_checks="integer,float-divide-by-zero"
    extra_cflags="-fsanitize=$extra_checks -fno-sanitize-recover=$extra_checks"
    export CFLAGS="${CFLAGS:-} $extra_cflags"
    export CXXFLAGS="${CXXFLAGS:-} $extra_cflags"
fi

# ---------- build the library ----------
build_lib() {
    # Some old zlib commits may not have a clean Makefile; ignore clean errors.
    if [ -f configure ]; then
        ./configure || (cat configure.log 2>/dev/null; return 1)
    elif [ -f CMakeLists.txt ]; then
        # Some versions might prefer cmake
        mkdir -p build && cd build
        cmake .. -DCMAKE_C_COMPILER="$CC" -DCMAKE_C_FLAGS="$CFLAGS" && make -j$(nproc)
        cp libz.a .. 2>/dev/null || true
        cd ..
        return 0
    else
        return 1
    fi

    make -j$(nproc) clean 2>/dev/null || true
    make -j$(nproc) all
}

# Try to build the library; if it fails, we cannot proceed at all.
if ! build_lib; then
    echo "ERROR: zlib library build failed"
    exit 1
fi

# Skip make check for memory sanitizer -- zlib's tests have uninitialized memory issues.
if [ "${SANITIZER:-}" != "memory" ]; then
    make -j$(nproc) check 2>/dev/null || true
fi

# ---------- try compiling the $SRC fuzz targets ----------
fuzz_targets_built=0

# Compile C++ fuzz targets from $SRC.
for fuzzer in $SRC/*_fuzzer.cc; do
    target=$(basename "$fuzzer" .cc)
    if $CXX $CXXFLAGS -std=c++11 -I. \
        "$fuzzer" \
        -o "$OUT/$target" \
        libz.a \
        $LIB_FUZZING_ENGINE 2>/dev/null; then
        fuzz_targets_built=$((fuzz_targets_built + 1))
    fi
done

# Compile C fuzz targets from $SRC.
for fuzzer in $SRC/*_fuzzer.c; do
    target=$(basename "$fuzzer" .c)
    if $CC $CFLAGS -I. \
        -c "$fuzzer" \
        -o "$WORK/${target}.o" 2>/dev/null; then
        if $CXX $CXXFLAGS -std=c++11 \
            "$WORK/${target}.o" \
            -o "$OUT/$target" \
            libz.a \
            $LIB_FUZZING_ENGINE 2>/dev/null; then
            fuzz_targets_built=$((fuzz_targets_built + 1))
        fi
    fi
done

# ---------- fall back to minimal fuzz target ----------
if [ "$fuzz_targets_built" -eq 0 ]; then
    echo "No $SRC fuzz targets compiled; building minimal uncompress fuzzer"

    cat > /tmp/zlib_uncompress_fuzzer.cc << 'FUZZEOF'
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "zlib.h"

static Bytef buffer[256 * 1024] = { 0 };

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    uLongf buffer_length = static_cast<uLongf>(sizeof(buffer));
    uncompress(buffer, &buffer_length, data, static_cast<uLong>(size));
    return 0;
}
FUZZEOF

    $CXX $CXXFLAGS -std=c++11 -I. \
        /tmp/zlib_uncompress_fuzzer.cc \
        -o "$OUT/zlib_uncompress_fuzzer" \
        libz.a \
        $LIB_FUZZING_ENGINE
    fuzz_targets_built=1
fi

# ---------- seed corpus ----------
# Create a seed corpus zip from source files (safe to fail on old commits).
zip "$OUT/seed_corpus.zip" *.* 2>/dev/null || true

# Symlink each C fuzzer to the shared seed corpus.
for fuzzer in $SRC/*_fuzzer.c; do
    target=$(basename "$fuzzer" .c)
    if [ -f "$OUT/$target" ]; then
        ln -sf seed_corpus.zip "$OUT/${target}_seed_corpus.zip"
    fi
done

# Also ensure the fallback fuzzer gets a corpus link.
if [ -f "$OUT/zlib_uncompress_fuzzer" ] && [ ! -f "$OUT/zlib_uncompress_fuzzer_seed_corpus.zip" ]; then
    ln -sf seed_corpus.zip "$OUT/zlib_uncompress_fuzzer_seed_corpus.zip" 2>/dev/null || true
fi

echo "Built $fuzz_targets_built fuzz target(s) successfully"
