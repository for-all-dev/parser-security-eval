#!/bin/bash -eu
# Build script for libpng fuzz targets.
#
# Works across old and new libpng versions. When checking out old
# vulnerable commits the in-tree contrib/oss-fuzz layout or autotools
# files may not exist. Strategy:
#   1. Try the in-tree contrib/oss-fuzz build first.
#   2. Fall back to building the library + a minimal fuzz target.
#
# Available environment variables (set by oss-fuzz base-builder):
#   $CC, $CXX           - compiler (clang with sanitizer flags)
#   $CFLAGS, $CXXFLAGS  - compiler flags (include sanitizer flags)
#   $LIB_FUZZING_ENGINE - path to fuzzing engine library
#   $OUT                - output directory for fuzz targets
#   $SRC                - source directory (/src)
#   $WORK               - working directory for build artifacts
################################################################################

# ---------- UBSan extra flags ----------
if [ "${SANITIZER:-}" = "undefined" ]; then
    extra_checks="integer,float-divide-by-zero"
    extra_cflags="-fsanitize=$extra_checks -fno-sanitize-recover=$extra_checks"
    export CFLAGS="${CFLAGS:-} $extra_cflags"
    export CXXFLAGS="${CXXFLAGS:-} $extra_cflags"
fi

# ---------- build zlib (dependency) ----------
cd /src/zlib
./configure --static --prefix=$WORK
make -j$(nproc)
make install

cd /src/libpng

# ---------- try in-tree oss-fuzz build first ----------
if [ -f contrib/oss-fuzz/build.sh ]; then
    echo "Trying in-tree contrib/oss-fuzz/build.sh ..."
    if bash contrib/oss-fuzz/build.sh; then
        echo "In-tree fuzz build succeeded."
        exit 0
    fi
    echo "In-tree fuzz build failed, falling back to manual build."
    # Clean up any partial build artifacts so we start fresh.
    make clean 2>/dev/null || true
fi

# ---------- build libpng library ----------
# Disable logging/write via pnglibconf.dfa when it exists (newer versions).
if [ -f scripts/pnglibconf.dfa ]; then
    sed -i \
        -e "s/option STDIO/option STDIO disabled/" \
        -e "s/option WARNING /option WARNING disabled/" \
        -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
        scripts/pnglibconf.dfa
fi

# Try autoreconf + configure (works on most versions).
build_ok=false
if [ -f configure.ac ] || [ -f configure.in ]; then
    if autoreconf -f -i 2>/dev/null; then
        if ./configure \
            CC="$CC" \
            CFLAGS="$CFLAGS" \
            CPPFLAGS="-I$WORK/include" \
            LDFLAGS="-L$WORK/lib" \
            --with-zlib-prefix=$WORK \
            --disable-shared 2>/dev/null; then
            make -j$(nproc) clean 2>/dev/null || true
            if make -j$(nproc); then
                build_ok=true
            fi
        fi
    fi
fi

# Fallback: cmake
if [ "$build_ok" = false ] && [ -f CMakeLists.txt ]; then
    mkdir -p build_cmake && cd build_cmake
    cmake .. \
        -DCMAKE_C_COMPILER="$CC" \
        -DCMAKE_C_FLAGS="$CFLAGS" \
        -DZLIB_ROOT="$WORK" \
        -DPNG_SHARED=OFF \
        -DPNG_STATIC=ON \
        -DPNG_TESTS=OFF
    make -j$(nproc)
    cd /src/libpng
    build_ok=true
fi

# Last resort: compile just the .c files into a static library
if [ "$build_ok" = false ]; then
    echo "autotools and cmake unavailable; compiling libpng sources directly."
    # Generate pnglibconf.h from the pre-built script if possible
    if [ -f scripts/pnglibconf.h.prebuilt ]; then
        cp scripts/pnglibconf.h.prebuilt pnglibconf.h
    elif [ ! -f pnglibconf.h ]; then
        # Minimal pnglibconf.h for old versions
        echo "#ifndef PNGLCONF_H" > pnglibconf.h
        echo "#define PNGLCONF_H" >> pnglibconf.h
        echo "#define PNG_READ_SUPPORTED" >> pnglibconf.h
        echo "#endif" >> pnglibconf.h
    fi

    $CC $CFLAGS -I. -I$WORK/include -c png.c pngerror.c pngget.c \
        pngmem.c pngpread.c pngread.c pngrio.c pngrtran.c pngrutil.c \
        pngset.c pngtrans.c 2>/dev/null || \
    $CC $CFLAGS -I. -I$WORK/include -c png.c pngerror.c pngget.c \
        pngmem.c pngread.c pngrio.c pngrtran.c pngrutil.c \
        pngset.c pngtrans.c
    ar rcs libpng.a png*.o
    build_ok=true
fi

# ---------- locate the built static library ----------
LIBPNG_A=""
for candidate in \
    /src/libpng/.libs/libpng16.a \
    /src/libpng/.libs/libpng.a \
    /src/libpng/build_cmake/libpng16.a \
    /src/libpng/build_cmake/libpng.a \
    /src/libpng/libpng.a; do
    if [ -f "$candidate" ]; then
        LIBPNG_A="$candidate"
        break
    fi
done

if [ -z "$LIBPNG_A" ]; then
    echo "ERROR: could not find libpng static library" >&2
    exit 1
fi

echo "Using libpng at $LIBPNG_A"

# ---------- build fuzz targets from contrib/oss-fuzz if present ----------
built_targets=false
if [ -d contrib/oss-fuzz ]; then
    for f in contrib/oss-fuzz/*_fuzzer.cc; do
        [ -f "$f" ] || continue
        name=$(basename "$f" .cc)
        echo "Building $name from in-tree source ..."
        if $CXX $CXXFLAGS -std=c++11 -I. -I$WORK/include \
            "$f" \
            -o "$OUT/$name" \
            $LIB_FUZZING_ENGINE "$LIBPNG_A" $WORK/lib/libz.a 2>/dev/null; then
            built_targets=true

            # Seed corpus
            find /src/libpng -name "*.png" -size -100k 2>/dev/null | \
                xargs zip "$OUT/${name}_seed_corpus.zip" 2>/dev/null || true

            # Dictionary
            if [ -f contrib/oss-fuzz/png.dict ]; then
                cp contrib/oss-fuzz/png.dict "$OUT/${name}.dict"
            fi
        else
            echo "  Warning: failed to build $name, skipping."
        fi
    done
fi

# ---------- minimal fallback fuzz target ----------
if [ "$built_targets" = false ]; then
    echo "Building minimal fallback fuzz target ..."
    cat > /tmp/png_read_fuzzer.c << 'FUZZEOF'
#include <png.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

struct png_mem_reader {
    const uint8_t *data;
    size_t size;
    size_t pos;
};

static void png_mem_read(png_structp png, png_bytep out, size_t count) {
    struct png_mem_reader *r = (struct png_mem_reader *)png_get_io_ptr(png);
    if (r->pos + count > r->size) {
        png_error(png, "read past end");
        return;
    }
    memcpy(out, r->data + r->pos, count);
    r->pos += count;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    png_structp png;
    png_infop info;
    struct png_mem_reader reader;

    if (size < 8) return 0;

    /* Check PNG signature */
    if (png_sig_cmp(data, 0, 8) != 0) return 0;

    png = png_create_read_struct(PNG_LIBPNG_VER_STRING, NULL, NULL, NULL);
    if (!png) return 0;

    info = png_create_info_struct(png);
    if (!info) {
        png_destroy_read_struct(&png, NULL, NULL);
        return 0;
    }

    if (setjmp(png_jmpbuf(png))) {
        png_destroy_read_struct(&png, &info, NULL);
        return 0;
    }

    reader.data = data;
    reader.size = size;
    reader.pos = 0;

    png_set_read_fn(png, &reader, png_mem_read);
    png_read_info(png, info);

    png_destroy_read_struct(&png, &info, NULL);
    return 0;
}
FUZZEOF

    $CC $CFLAGS -I. -I$WORK/include \
        -c /tmp/png_read_fuzzer.c -o /tmp/png_read_fuzzer.o

    $CXX $CXXFLAGS \
        /tmp/png_read_fuzzer.o \
        -o "$OUT/libpng_read_fuzzer" \
        $LIB_FUZZING_ENGINE "$LIBPNG_A" $WORK/lib/libz.a

    # Seed corpus from any PNG files in the source tree
    find /src/libpng -name "*.png" -size -100k 2>/dev/null | \
        xargs zip "$OUT/libpng_read_fuzzer_seed_corpus.zip" 2>/dev/null || true
fi

# ---------- copy dictionaries and options ----------
if compgen -G "/src/libpng/contrib/oss-fuzz/*.dict" > /dev/null 2>&1; then
    cp /src/libpng/contrib/oss-fuzz/*.dict "$OUT/" 2>/dev/null || true
fi
if compgen -G "/src/libpng/contrib/oss-fuzz/*.options" > /dev/null 2>&1; then
    cp /src/libpng/contrib/oss-fuzz/*.options "$OUT/" 2>/dev/null || true
fi
