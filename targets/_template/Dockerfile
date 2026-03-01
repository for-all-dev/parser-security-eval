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
# Full clone (no --depth 1) so we can checkout vulnerable commits.
# RUN git clone <repo-url> /src/<project>
# COPY src/ /src/<project>/

WORKDIR /src

COPY build.sh $SRC/
