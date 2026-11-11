# Nightjar engine image for lizard (cyclomatic complexity and duplicate code, 30+ languages),
# installed from the pinned release source tarball verified by SHA-256. lizard is MIT-licensed.
#
#   docker build -t nightjar-engines/lizard:1.24.3 engines/lizard
#
# Bumped automatically by `nightjar engines watch` (VERSION and SOURCE_SHA256).
FROM mirror.gcr.io/library/python:3.12-slim@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b

ARG VERSION=1.24.3
ARG SOURCE_SHA256=1cea733ac0b051d78ae2fdffaaf7757658bfb1b186c948e6e4a03a05874d8507

COPY requirements.txt /tmp/requirements.txt
RUN set -eu; \
    apt-get update; apt-get upgrade -y --no-install-recommends; rm -rf /var/lib/apt/lists/*; \
    pip install --no-cache-dir --require-hashes --only-binary=:all: -r /tmp/requirements.txt; \
    python -c "import urllib.request; urllib.request.urlretrieve('https://github.com/terryyin/lizard/archive/refs/tags/${VERSION}.tar.gz', '/tmp/lizard.tgz')"; \
    echo "${SOURCE_SHA256}  /tmp/lizard.tgz" | sha256sum -c -; \
    pip install --no-cache-dir --no-deps /tmp/lizard.tgz; \
    rm /tmp/lizard.tgz

# Unprivileged: the engine only reads the mounted source and writes to the work folder.
USER 65532:65532
ENV HOME=/tmp
ENTRYPOINT ["lizard"]
