FROM gcr.io/oss-fuzz-base/base-builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    make cmake pkg-config

RUN git clone --depth 1 https://github.com/PCRE2Project/pcre2.git /src/pcre2

WORKDIR /src/pcre2
COPY build.sh $SRC/
