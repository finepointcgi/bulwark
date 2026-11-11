# Bulwark engine image for nuclei, with a pinned, hash-verified template set baked in.
#
# Why not the upstream image: it downloads the latest templates at run time (unreproducible,
# needs internet during a test), runs as root, and ships with OS packages and a Go standard
# library that have known CVEs. This image builds nuclei from source with a patched Go
# toolchain, on a fully upgraded Alpine base, and runs unprivileged. It never updates itself.
#
#   docker build -t bulwark-engines/nuclei:v3.11.1 engines/nuclei
#
# To bump: change NUCLEI_VERSION, the Go and Alpine tags, TEMPLATES_VERSION and
# TEMPLATES_SHA256 (sha256 of the GitHub release tarball), then update the manifest digest.

FROM mirror.gcr.io/library/golang:1.26.11-alpine@sha256:ae52b5bc6ed045a9ed26ab03dc19327a802a9cc9aa8b27ed57f5c6b60579b0bb AS build
ARG NUCLEI_VERSION=v3.11.1
# GOTOOLCHAIN=local: compile with this image's patched standard library, never a downloaded one.
# Module downloads are verified against the Go checksum database (sum.golang.org).
ENV CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=-trimpath
RUN go install -ldflags="-s -w" "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@${NUCLEI_VERSION}"

FROM mirror.gcr.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf AS templates
ARG TEMPLATES_VERSION=10.5.1
ARG TEMPLATES_SHA256=30fe1cfaced4635f886e4a2673641bba86998dceec28e468274524e789aa56eb
RUN set -eu; \
    apk add --no-cache curl; \
    curl -fsSL -o /tmp/templates.tgz "https://github.com/projectdiscovery/nuclei-templates/archive/refs/tags/v${TEMPLATES_VERSION}.tar.gz"; \
    echo "${TEMPLATES_SHA256}  /tmp/templates.tgz" | sha256sum -c -; \
    mkdir -p /templates; \
    tar -xzf /tmp/templates.tgz -C /templates --strip-components=1

FROM mirror.gcr.io/library/alpine:3.24.4@sha256:f59abe656b692d901e184be3445e084786602108599d2a51d229c0f5a48c71bf
RUN apk upgrade --no-cache && apk add --no-cache ca-certificates
COPY --from=build /go/bin/nuclei /usr/local/bin/nuclei
COPY --from=templates --chmod=a+rX /templates /templates

# Unprivileged, like Bulwark's other engine images. nuclei writes its config and cache under HOME.
USER 65532:65532
ENV HOME=/tmp
ENTRYPOINT ["nuclei"]
