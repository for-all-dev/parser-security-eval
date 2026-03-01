# Template Dockerfile for parser targets.
# Copy this directory and customize for each parser.
#
# Follows oss-fuzz conventions:
# https://google.github.io/oss-fuzz/getting-started/new-project-guide/
#
FROM gcr.io/oss-fuzz-base/base-builder

# Install target-specific dependencies
# RUN apt-get update && apt-get install -y <packages>

# Clone or copy target source
# RUN git clone --depth 1 <repo-url> /src/<project>
# COPY src/ /src/<project>/

# Optional: install CASR for crash triage
# RUN cargo install casr --locked
# or: RUN apt-get install -y ... (if a deb is available)

WORKDIR /src

COPY build.sh $SRC/
