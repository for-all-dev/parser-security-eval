# Copyright 2016 Google Inc.
# Copyright 2022-2023 D. R. Commander
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
################################################################################
#
# Adapted from https://github.com/google/oss-fuzz/tree/master/projects/libjpeg-turbo

FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y make yasm cmake

# Clone the libjpeg-turbo fuzz scripts and the main branch of the library
RUN git clone --depth 1 https://github.com/libjpeg-turbo/fuzz && \
    git clone --depth 1 https://github.com/libjpeg-turbo/libjpeg-turbo -b main libjpeg-turbo.main

# Build seed corpora from the upstream seed-corpora repository
RUN git clone --depth 1 https://github.com/libjpeg-turbo/seed-corpora && \
    cd seed-corpora && \
    zip -r ../decompress_fuzzer_seed_corpus.zip afl-testcases/jpeg* bugs/decompress* && \
    cd /src && \
    zip -r decompress_fuzzer_seed_corpus.zip libjpeg-turbo.main/testimages/*.jpg && \
    cd seed-corpora && \
    zip -r ../compress_fuzzer_seed_corpus.zip afl-testcases/bmp afl-testcases/gif* afl-testcases/targa bugs/compress* && \
    cd /src && \
    zip -r compress_fuzzer_seed_corpus.zip libjpeg-turbo.main/testimages/*.bmp \
        libjpeg-turbo.main/testimages/*.ppm \
        libjpeg-turbo.main/testimages/*.pgm && \
    rm -rf /src/seed-corpora

WORKDIR /src

COPY build.sh $SRC/
