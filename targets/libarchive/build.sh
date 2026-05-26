#!/bin/bash -eu

cd /src/libarchive

cmake . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DENABLE_TEST=OFF

make -j$(nproc) archive_static

cat > /tmp/libarchive_fuzzer.cc << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <archive.h>
#include <archive_entry.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct archive *a = archive_read_new();
    archive_read_support_filter_all(a);
    archive_read_support_format_all(a);

    if (archive_read_open_memory(a, data, size) == ARCHIVE_OK) {
        struct archive_entry *entry;
        while (archive_read_next_header(a, &entry) == ARCHIVE_OK) {
            archive_read_data_skip(a);
        }
    }
    archive_read_free(a);
    return 0;
}
EOF

$CXX $CXXFLAGS -I/src/libarchive/libarchive \
    /tmp/libarchive_fuzzer.cc \
    -o $OUT/libarchive_fuzzer \
    $LIB_FUZZING_ENGINE \
    /src/libarchive/libarchive/libarchive.a \
    -lz -lbz2 -llzma -llz4 -lzstd -lcrypto -lxml2
