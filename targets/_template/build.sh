#!/bin/bash -eu
# Template build.sh for parser targets.
# Follows oss-fuzz conventions.
#
# Available environment variables (set by base-builder):
#   $CC, $CXX           — compiler (clang with sanitizer flags)
#   $CFLAGS, $CXXFLAGS  — compiler flags (include sanitizer flags)
#   $LIB_FUZZING_ENGINE — path to fuzzing engine library
#   $OUT                — output directory for fuzz targets
#   $SRC                — source directory
#   $WORK               — working directory for build artifacts

# Example: build the project
# cd /src/<project>
# mkdir build && cd build
# cmake .. -DCMAKE_C_COMPILER=$CC -DCMAKE_CXX_COMPILER=$CXX
# make -j$(nproc)

# Example: compile fuzz target
# $CXX $CXXFLAGS -I/src/<project>/include \
#   /src/<project>/fuzz_target.cc \
#   -o $OUT/fuzz_target \
#   /src/<project>/build/lib<project>.a \
#   $LIB_FUZZING_ENGINE

echo "ERROR: build.sh not configured. Copy _template/ and customize."
exit 1
