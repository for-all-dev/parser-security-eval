#!/bin/bash -eu

cd /src/pcre2

cmake . \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_C_COMPILER="$CC" \
    -DCMAKE_CXX_COMPILER="$CXX" \
    -DCMAKE_C_FLAGS="$CFLAGS" \
    -DCMAKE_CXX_FLAGS="$CXXFLAGS" \
    -DPCRE2_BUILD_TESTS=OFF \
    -DPCRE2_SUPPORT_JIT=ON \
    -DPCRE2_BUILD_PCRE2_8=ON

make -j$(nproc)

cat > /tmp/pcre2_fuzzer.cc << 'EOF'
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#define PCRE2_CODE_UNIT_WIDTH 8
#include <pcre2.h>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    if (size < 1) return 0;

    // Split input: first byte determines split point
    size_t split = data[0] % (size > 1 ? size - 1 : 1) + 1;
    if (split >= size) split = size / 2;

    // Pattern from first part, subject from second
    std::string pattern((const char *)data + 1, split > 1 ? split - 1 : 0);
    std::string subject((const char *)data + split, size - split);

    int errcode;
    PCRE2_SIZE erroffset;
    pcre2_code *re = pcre2_compile(
        (PCRE2_SPTR)pattern.c_str(), PCRE2_ZERO_TERMINATED,
        0, &errcode, &erroffset, NULL);

    if (re) {
        pcre2_match_data *match_data = pcre2_match_data_create_from_pattern(re, NULL);
        pcre2_match(re, (PCRE2_SPTR)subject.c_str(), subject.size(),
                    0, 0, match_data, NULL);
        pcre2_match_data_free(match_data);
        pcre2_code_free(re);
    }
    return 0;
}
EOF

$CXX $CXXFLAGS \
    -I/src/pcre2/src \
    /tmp/pcre2_fuzzer.cc \
    -o $OUT/pcre2_fuzzer \
    $LIB_FUZZING_ENGINE \
    /src/pcre2/libpcre2-8.a
