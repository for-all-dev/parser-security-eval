#!/bin/bash -eu

cd /src/libexpat/expat

cmake . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DEXPAT_BUILD_TESTS=OFF \
    -DEXPAT_BUILD_TOOLS=OFF \
    -DEXPAT_BUILD_EXAMPLES=OFF \
    -DEXPAT_SHARED_LIBS=OFF

make -j$(nproc)

cat > /tmp/expat_fuzzer.cc << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <expat.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    XML_Parser parser = XML_ParserCreate(NULL);
    XML_Parse(parser, (const char *)data, size, 1);
    XML_ParserFree(parser);
    return 0;
}
EOF

$CXX $CXXFLAGS \
    -I/src/libexpat/expat/lib \
    /tmp/expat_fuzzer.cc \
    -o $OUT/expat_fuzzer \
    $LIB_FUZZING_ENGINE \
    /src/libexpat/expat/libexpat.a
