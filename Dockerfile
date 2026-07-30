FROM rust:bookworm AS contracts

WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY sdks/rust ./sdks/rust
RUN mkdir -p /openapi \
    && cargo run --quiet --locked --package owlauth-types --bin export-openapi -- runtime /openapi/runtime.json \
    && cargo run --quiet --locked --package owlauth-types --bin export-openapi -- control /openapi/control.json

FROM node:24-bookworm-slim AS web-builder

WORKDIR /workspace
RUN npm install --global pnpm@11.17.0
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY crates/owlauth-server/web/package.json crates/owlauth-server/web/package.json
RUN pnpm install --filter @owlauth/server-web... --frozen-lockfile
COPY crates/owlauth-server/web crates/owlauth-server/web
COPY --from=contracts /openapi target/openapi
WORKDIR /workspace/crates/owlauth-server/web
RUN node scripts/generate-contracts.mjs --check \
    && pnpm run boundaries:check \
    && pnpm run typecheck \
    && pnpm run build:runtime \
    && pnpm run build:control \
    && pnpm run prepare:assets

FROM rust:bookworm AS rust-builder

WORKDIR /workspace
COPY Cargo.toml Cargo.lock rust-toolchain.toml ./
COPY crates ./crates
COPY sdks/rust ./sdks/rust
RUN rm -rf crates/owlauth-server/web/dist
COPY --from=web-builder /workspace/crates/owlauth-server/web/dist crates/owlauth-server/web/dist
RUN cargo build --release --locked --package owlauth-server

FROM debian:bookworm-slim AS runtime

ARG OWLAUTH_VERSION=dev
ARG VCS_REF=unknown
ARG SOURCE_URL=https://github.com/owlfoundry/owlauth

LABEL org.opencontainers.image.title="OwlAuth" \
      org.opencontainers.image.description="Self-hostable Project Auth and identity infrastructure" \
      org.opencontainers.image.source="${SOURCE_URL}" \
      org.opencontainers.image.version="${OWLAUTH_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.licenses="BSD-3-Clause"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends ca-certificates curl tini \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --gid 10001 owlauth \
    && useradd --uid 10001 --gid owlauth --no-create-home --home-dir /nonexistent --shell /usr/sbin/nologin owlauth

COPY --from=rust-builder --chown=owlauth:owlauth /workspace/target/release/owlauth-server /usr/local/bin/owlauth-server
COPY --chown=owlauth:owlauth LICENSE /usr/share/licenses/owlauth/LICENSE

USER owlauth
ENV OWLAUTH_MODE=runtime \
    OWLAUTH_RUNTIME_ADDR=0.0.0.0:8080
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD curl --fail --silent --show-error http://127.0.0.1:8080/health >/dev/null || exit 1
ENTRYPOINT ["/usr/bin/tini", "--", "/usr/local/bin/owlauth-server"]
