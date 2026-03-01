#!/bin/bash -eu
# Build script for libjpeg-turbo fuzz targets.
#
# Hardened to work when `git checkout <vulnerable_ref>` rolls the source tree
# back to an old commit. Tries the in-tree fuzz build first (modern commits
# with -DWITH_FUZZ=1), then falls back to building a minimal JPEG
# decompression fuzz target from scratch.
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

# Resolve the source directory -- handle both libjpeg-turbo.main (upstream
# oss-fuzz convention) and libjpeg-turbo (our eval convention via symlink).
if [ -d "$SRC/libjpeg-turbo.main" ]; then
    SRCDIR="$SRC/libjpeg-turbo.main"
elif [ -d "$SRC/libjpeg-turbo" ]; then
    SRCDIR="$SRC/libjpeg-turbo"
else
    echo "FATAL: cannot find libjpeg-turbo source directory" >&2
    exit 1
fi

cd "$SRCDIR"

# ---------- UBSan extra flags ----------
if [ "${SANITIZER:-}" = "undefined" ]; then
    extra_checks="integer,float-divide-by-zero"
    extra_cflags="-fsanitize=$extra_checks -fno-sanitize-recover=$extra_checks"
    export CFLAGS="${CFLAGS:-} $extra_cflags"
    export CXXFLAGS="${CXXFLAGS:-} $extra_cflags"
fi

# ---------- MSan zero-buffers ----------
if [ "${SANITIZER:-}" = "memory" ]; then
    export CFLAGS="${CFLAGS:-} -DZERO_BUFFERS=1"
fi

# ---------- try in-tree fuzz build first (modern commits) ----------
# Modern libjpeg-turbo supports -DWITH_FUZZ=1 which builds all fuzz targets.
try_intree_build() {
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
        -DFUZZER_SUFFIX="" \
    && make "-j$(nproc)" "--load-average=$(nproc)" \
    && make install
}

if try_intree_build; then
    # Attach seed corpora for compression fuzz targets
    for fuzzer in cjpeg \
                  compress \
                  compress_yuv \
                  compress_lossless \
                  compress12 \
                  compress12_lossless \
                  compress16_lossless; do
        if [ -f "$OUT/${fuzzer}_fuzzer" ]; then
            cp "$SRC/compress_fuzzer_seed_corpus.zip" \
               "$OUT/${fuzzer}_fuzzer_seed_corpus.zip" 2>/dev/null || true
        fi
    done

    # Attach seed corpora and dictionaries for decompression fuzz targets
    for fuzzer in libjpeg_turbo \
                  decompress_libjpeg \
                  decompress_yuv \
                  transform; do
        if [ -f "$OUT/${fuzzer}_fuzzer" ]; then
            cp "$SRC/decompress_fuzzer_seed_corpus.zip" \
               "$OUT/${fuzzer}_fuzzer_seed_corpus.zip" 2>/dev/null || true
            if [ -f "$SRCDIR/fuzz/jpeg.dict" ]; then
                cp "$SRCDIR/fuzz/jpeg.dict" \
                   "$OUT/${fuzzer}_fuzzer.dict" 2>/dev/null || true
            fi
        fi
    done
    exit 0
fi

echo "In-tree fuzz build failed, falling back to minimal fuzz target"

# ---------- clean up failed cmake artifacts ----------
rm -f CMakeCache.txt
rm -rf CMakeFiles

# ---------- build library without fuzz targets ----------
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
    -DCMAKE_INSTALL_PREFIX="$WORK"

make "-j$(nproc)" "--load-average=$(nproc)"
make install

# ---------- build minimal JPEG decompression fuzz target ----------
# Works with any libjpeg-turbo version (uses the stable libjpeg API).
cat > /tmp/libjpeg_turbo_fuzz.cc << 'FUZZEOF'
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

extern "C" {
#include <jpeglib.h>
}

// Custom error handler that longjmps instead of calling exit().
struct fuzz_error_mgr {
    struct jpeg_error_mgr pub;
    jmp_buf setjmp_buffer;
};

#include <setjmp.h>

static void fuzz_error_exit(j_common_ptr cinfo) {
    struct fuzz_error_mgr *myerr = (struct fuzz_error_mgr *)cinfo->err;
    longjmp(myerr->setjmp_buffer, 1);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    struct jpeg_decompress_struct cinfo;
    struct fuzz_error_mgr jerr;

    if (size < 2) return 0;

    cinfo.err = jpeg_std_error(&jerr.pub);
    jerr.pub.error_exit = fuzz_error_exit;

    if (setjmp(jerr.setjmp_buffer)) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }

    jpeg_create_decompress(&cinfo);
    jpeg_mem_src(&cinfo, data, size);

    if (jpeg_read_header(&cinfo, TRUE) != JPEG_HEADER_OK) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }

    cinfo.out_color_space = JCS_RGB;

    if (!jpeg_start_decompress(&cinfo)) {
        jpeg_destroy_decompress(&cinfo);
        return 0;
    }

    int row_stride = cinfo.output_width * cinfo.output_components;
    JSAMPARRAY buffer = (*cinfo.mem->alloc_sarray)(
        (j_common_ptr)&cinfo, JPOOL_IMAGE, row_stride, 1);

    while (cinfo.output_scanline < cinfo.output_height) {
        jpeg_read_scanlines(&cinfo, buffer, 1);
    }

    jpeg_finish_decompress(&cinfo);
    jpeg_destroy_decompress(&cinfo);

    return 0;
}
FUZZEOF

$CXX $CXXFLAGS -I"$WORK/include" -c /tmp/libjpeg_turbo_fuzz.cc -o /tmp/libjpeg_turbo_fuzz.o

$CXX $CXXFLAGS \
    /tmp/libjpeg_turbo_fuzz.o \
    -o "$OUT/libjpeg_turbo_fuzzer" \
    $LIB_FUZZING_ENGINE \
    "$WORK/lib/libjpeg.a" -Wl,-Bstatic -Wl,-Bdynamic

# Seed corpus for the decompression target
if [ -f "$SRC/decompress_fuzzer_seed_corpus.zip" ]; then
    cp "$SRC/decompress_fuzzer_seed_corpus.zip" \
       "$OUT/libjpeg_turbo_fuzzer_seed_corpus.zip"
fi

# Dictionary if available
if [ -f "$SRCDIR/fuzz/jpeg.dict" ]; then
    cp "$SRCDIR/fuzz/jpeg.dict" "$OUT/libjpeg_turbo_fuzzer.dict"
fi
