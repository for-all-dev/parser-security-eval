FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    make cmake pkg-config

RUN git clone --depth 1 https://github.com/libexpat/libexpat.git /src/libexpat

WORKDIR /src/libexpat
COPY build.sh $SRC/
