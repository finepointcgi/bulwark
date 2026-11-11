# Nightjar engine image for cppcheck (C/C++ static analysis), built from the pinned release
# source tarball verified by SHA-256. cppcheck is GPL-3.0; Nightjar only runs it as a separate
# process in this container, it never links it.
#
#   docker build -t nightjar-engines/cppcheck:2.22.0 engines/cppcheck
#
# Bumped automatically by `nightjar engines watch` (VERSION and SOURCE_SHA256).
FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc AS build

ARG VERSION=2.22.0
ARG SOURCE_SHA256=d74945deb2d50393430e07596b766f8a779512c7f60dac2a30ea64e059ece57b

RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl cmake g++ make python3; \
    curl -fsSL -o /tmp/cppcheck.tgz "https://github.com/cppcheck-opensource/cppcheck/archive/refs/tags/${VERSION}.tar.gz"; \
    echo "${SOURCE_SHA256}  /tmp/cppcheck.tgz" | sha256sum -c -; \
    mkdir /src; tar -xzf /tmp/cppcheck.tgz -C /src --strip-components=1; \
    cmake -S /src -B /build -DCMAKE_BUILD_TYPE=Release -DUSE_MATCHCOMPILER=On -DHAVE_RULES=Off \
      -DBUILD_GUI=Off -DBUILD_TESTS=Off -DFILESDIR=/usr/local/share/Cppcheck; \
    cmake --build /build --parallel "$(nproc)"; \
    cmake --install /build

FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=build /usr/local/bin/cppcheck /usr/local/bin/cppcheck
COPY --from=build /usr/local/share/Cppcheck /usr/local/share/Cppcheck
# Unprivileged: the engine only reads the mounted source and writes to the work folder.
USER 65532:65532
ENV HOME=/tmp
ENTRYPOINT ["cppcheck"]
