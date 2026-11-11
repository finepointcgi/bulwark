# Bulwark engine image for Opengrep. Opengrep publishes signed release binaries but no
# container image, so Bulwark builds one from the pinned binary, verified by SHA-256.
#
#   docker build -t bulwark-engines/opengrep:v1.33.1 engines/opengrep
#
# To bump: change VERSION and both hashes (from the release's asset digests), then
# update the manifest with the new image digest.
FROM mirror.gcr.io/library/debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc

ARG TARGETARCH
ARG VERSION=v1.33.1
ARG SHA256_AMD64=46e8133cc490f9f50518061590ce2f6be5a08afaeda034471c0ceda4b3899808
ARG SHA256_ARM64=d1433f63a90b8bc0b6ad4b498a13b372b856ce9a754a43484ba4920fe2d76dcf

RUN set -eu; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    case "${TARGETARCH:-amd64}" in \
      amd64) ASSET=opengrep_manylinux_x86; SHA="$SHA256_AMD64" ;; \
      arm64) ASSET=opengrep_manylinux_aarch64; SHA="$SHA256_ARM64" ;; \
      *) echo "unsupported architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /usr/local/bin/opengrep "https://github.com/opengrep/opengrep/releases/download/${VERSION}/${ASSET}"; \
    echo "${SHA}  /usr/local/bin/opengrep" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/opengrep; \
    apt-get purge -y curl; \
    apt-get autoremove -y; \
    rm -rf /var/lib/apt/lists/*

# Unprivileged: the engine only reads the mounted source and writes to the work folder.
USER 65532:65532
ENV HOME=/tmp
ENTRYPOINT ["opengrep"]
