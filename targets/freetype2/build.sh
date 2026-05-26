#!/bin/bash -eu

cd /src/freetype2

mkdir -p build && cd build

# Configure with CMake for oss-fuzz (out-of-source build)
cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DFT_DISABLE_ZLIB=FALSE \
    -DFT_DISABLE_BZIP2=FALSE \
    -DFT_DISABLE_PNG=FALSE \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS"

make -j$(nproc)

# Build fuzz target
cat > /tmp/freetype_fuzzer.cc << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <ft2build.h>
#include FT_FREETYPE_H

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    FT_Library library;
    FT_Face face;

    if (FT_Init_FreeType(&library)) return 0;

    FT_Open_Args args;
    args.flags = FT_OPEN_MEMORY;
    args.memory_base = data;
    args.memory_size = size;

    if (!FT_Open_Face(library, &args, 0, &face)) {
        FT_Done_Face(face);
    }
    FT_Done_FreeType(library);
    return 0;
}
EOF

$CXX $CXXFLAGS -I/src/freetype2/include \
    /tmp/freetype_fuzzer.cc \
    -o $OUT/freetype_fuzzer \
    $LIB_FUZZING_ENGINE \
    /src/freetype2/build/libfreetype.a \
    -lpng -lz -lbz2
