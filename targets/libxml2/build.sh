#!/bin/bash -eu
# Build script for libxml2 fuzz targets.
#
# Works with both old autotools-based versions and newer versions.
# If the in-tree fuzz/oss-fuzz-build.sh works, use it; otherwise
# fall back to building a minimal fuzz target from scratch.

cd /src/libxml2

# ---------- UBSan extra flags ----------
if [ "${SANITIZER:-}" = "undefined" ]; then
    extra_checks="integer,float-divide-by-zero"
    extra_cflags="-fsanitize=$extra_checks -fno-sanitize-recover=$extra_checks"
    export CFLAGS="${CFLAGS:-} $extra_cflags"
    export CXXFLAGS="${CXXFLAGS:-} $extra_cflags"
fi

# ---------- try in-tree build first ----------
if [ -f fuzz/oss-fuzz-build.sh ]; then
    if fuzz/oss-fuzz-build.sh; then
        exit 0
    fi
    echo "In-tree fuzz build failed, falling back to minimal target"
fi

# ---------- configure + build library ----------
if [ "${SANITIZER:-}" = "memory" ]; then
    CONFIG=''
else
    CONFIG='--with-zlib'
fi

export V=1
./autogen.sh \
    --disable-shared \
    --without-debug \
    --without-http \
    --without-python \
    $CONFIG

make -j$(nproc)

# ---------- build minimal fuzz target ----------
# This simple target works with any libxml2 version.
cat > /tmp/xml_fuzz.c << 'FUZZEOF'
#include <libxml/parser.h>
#include <libxml/xmlmemory.h>
#include <stdint.h>
#include <stdlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    xmlDocPtr doc;

    if (size < 1) return 0;

    doc = xmlReadMemory((const char *)data, (int)size,
                        "test.xml", NULL, 0);
    if (doc != NULL) {
        xmlFreeDoc(doc);
    }

    return 0;
}
FUZZEOF

$CC $CFLAGS -I./include -c /tmp/xml_fuzz.c -o /tmp/xml_fuzz.o

$CXX $CXXFLAGS \
    /tmp/xml_fuzz.o \
    -o "$OUT/xml" \
    $LIB_FUZZING_ENGINE \
    .libs/libxml2.a -Wl,-Bstatic -lz -llzma -Wl,-Bdynamic

# Seed corpus from test data if available
if [ -d test ]; then
    mkdir -p /tmp/xml_seeds
    find test -name '*.xml' -size -10k -exec cp {} /tmp/xml_seeds/ \; 2>/dev/null || true
    if [ "$(ls /tmp/xml_seeds/)" ]; then
        zip -j "$OUT/xml_seed_corpus.zip" /tmp/xml_seeds/* 2>/dev/null || true
    fi
fi
