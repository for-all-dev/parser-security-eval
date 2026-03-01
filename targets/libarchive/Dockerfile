FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    make cmake pkg-config \
    zlib1g-dev libbz2-dev liblzma-dev liblz4-dev \
    libzstd-dev libxml2-dev libacl1-dev

RUN git clone --depth 1 https://github.com/libarchive/libarchive.git /src/libarchive

WORKDIR /src/libarchive
COPY build.sh $SRC/
