#!/bin/bash -eu
# Copyright 2016 Google Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
################################################################################

shopt -s nullglob

cd /src/zlib

./configure || (cat configure.log && false)

make -j$(nproc) clean
make -j$(nproc) all

# Skip make check for memory sanitizer — zlib's tests have uninitialized memory issues.
if [ "$SANITIZER" != "memory" ]; then
  make -j$(nproc) check
fi

# Compile C++ fuzz targets.
for fuzzer in $SRC/*_fuzzer.cc; do
  target=$(basename "$fuzzer" .cc)
  $CXX $CXXFLAGS -std=c++11 -I. \
    "$fuzzer" \
    -o "$OUT/$target" \
    libz.a \
    $LIB_FUZZING_ENGINE
done

# Create a seed corpus zip from all source files.
zip $OUT/seed_corpus.zip *.*

# Compile C fuzz targets.
for fuzzer in $SRC/*_fuzzer.c; do
  target=$(basename "$fuzzer" .c)
  $CC $CFLAGS -I. \
    -c "$fuzzer" \
    -o "$WORK/${target}.o"
  $CXX $CXXFLAGS -std=c++11 \
    "$WORK/${target}.o" \
    -o "$OUT/$target" \
    libz.a \
    $LIB_FUZZING_ENGINE
  # Symlink each C fuzzer to the shared seed corpus.
  ln -sf seed_corpus.zip "$OUT/${target}_seed_corpus.zip"
done
