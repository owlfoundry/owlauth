FROM rust:bookworm AS builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock ./
COPY crates ./crates
COPY sdks/rust ./sdks/rust
RUN cargo build --release --locked --package owlauth

FROM debian:bookworm-slim AS runtime

ARG OWLAUTH_VERSION=dev
ARG VCS_REF=unknown
ARG SOURCE_URL=https://github.com/owlfoundry/owlauth

LABEL org.opencontainers.image.title="OwlAuth" \
      org.opencontainers.image.description="Self-hostable OAuth 2.1 authorization server and user management platform" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${OWLAUTH_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="BSD-3-Clause"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 owlauth \
    && useradd --uid 10001 --gid owlauth --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin owlauth

COPY --from=builder --chown=owlauth:owlauth /workspace/target/release/owlauth /usr/local/bin/owlauth
COPY --chown=owlauth:owlauth LICENSE /usr/share/licenses/owlauth/LICENSE

USER owlauth
ENV OWLAUTH_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/owlauth"]
