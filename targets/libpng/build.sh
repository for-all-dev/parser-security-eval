#!/bin/bash -eu
# Copyright 2017-2018 Glenn Randers-Pehrson
# Copyright 2016 Google Inc.
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
# Build script for libpng fuzz targets.
# Faithfully adapted from libpng/contrib/oss-fuzz/build.sh.
#
# Available environment variables (set by oss-fuzz base-builder):
#   $CC, $CXX           - compiler (clang with sanitizer flags)
#   $CFLAGS, $CXXFLAGS  - compiler flags (include sanitizer flags)
#   $LIB_FUZZING_ENGINE - path to fuzzing engine library
#   $OUT                - output directory for fuzz targets
#   $SRC                - source directory (/src)
#   $WORK               - working directory for build artifacts
################################################################################

cd /src/libpng

# Build zlib first (dependency of libpng)
cd /src/zlib
./configure --static --prefix=$WORK
make -j$(nproc)
make install

cd /src/libpng

# Disable logging via library build configuration control.
cat scripts/pnglibconf.dfa | \
  sed -e "s/option STDIO/option STDIO disabled/" \
      -e "s/option WARNING /option WARNING disabled/" \
      -e "s/option WRITE enables WRITE_INT_FUNCTIONS/option WRITE disabled/" \
  > scripts/pnglibconf.dfa.temp
mv scripts/pnglibconf.dfa.temp scripts/pnglibconf.dfa

# Build the libpng library.
autoreconf -f -i
./configure \
  CC="$CC" \
  CFLAGS="$CFLAGS" \
  --with-libpng-prefix=OSS_FUZZ_ \
  --with-zlib-prefix=$WORK
make -j$(nproc) clean
make -j$(nproc) libpng16.la

# Build fuzz targets.
for f in libpng_read_fuzzer \
          libpng_colormap_fuzzer \
          libpng_readapi_fuzzer \
          libpng_transformations_fuzzer; do
  $CXX $CXXFLAGS -std=c++11 -I. \
    $SRC/libpng/contrib/oss-fuzz/${f}.cc \
    -o $OUT/${f} \
    $LIB_FUZZING_ENGINE .libs/libpng16.a $WORK/lib/libz.a

  # Only libfuzzer can run the nalloc targets.
  if test "x${FUZZING_ENGINE:-}" = 'xlibfuzzer'; then
    # Wrapper script to run target with allocation failure injection.
    cat > $OUT/${f}_nalloc <<EOF
#!/bin/sh
# LLVMFuzzerTestOneInput for fuzzer detection.
this_dir=\$(dirname "\$0")
NALLOC_FREQ=32 \$this_dir/${f} "\$@"
EOF
    chmod +x $OUT/${f}_nalloc
  fi

  # Add seed corpus from any PNG files in the source tree.
  find $SRC/libpng -name "*.png" | \
    xargs zip $OUT/${f}_seed_corpus.zip

  if [ -f $SRC/libpng/contrib/oss-fuzz/png.dict ]; then
    cp $SRC/libpng/contrib/oss-fuzz/png.dict $OUT/${f}.dict
  fi
done

# Copy any dict or options files.
if compgen -G "$SRC/libpng/contrib/oss-fuzz/*.dict" > /dev/null; then
  cp $SRC/libpng/contrib/oss-fuzz/*.dict $OUT/
fi
if compgen -G "$SRC/libpng/contrib/oss-fuzz/*.options" > /dev/null; then
  cp $SRC/libpng/contrib/oss-fuzz/*.options $OUT/
fi
