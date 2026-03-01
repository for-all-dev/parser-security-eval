FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    make cmake pkg-config \
    libpng-dev zlib1g-dev libbz2-dev

RUN git clone --depth 1 https://gitlab.freedesktop.org/freetype/freetype.git /src/freetype

WORKDIR /src/freetype
COPY build.sh $SRC/
