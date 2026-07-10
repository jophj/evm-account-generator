# syntax=docker/dockerfile:1

# Docker Hardened Images. These base images require your org's DHI entitlement.
# Override the image args to point at a mirrored namespace (e.g. <org>/dhi-rust)
# if needed, and verify the exact tags in the DHI catalog before building.
#
# Build image: the dev variant adds the `-dev` suffix (e.g. `1.96.1-alpine3.23`
# -> `1.96.1-alpine3.23-dev`).
ARG RUST_IMAGE=dhi.io/rust
ARG RUST_TAG=1.96.1-alpine3.23

# Runtime image: a minimal Alpine base. The release binary is musl-linked and
# needs only a matching (musl/Alpine) userland plus libgcc_s.so.1 (copied from
# the build stage below).
ARG RUNTIME_IMAGE=dhi.io/alpine-base
ARG RUNTIME_TAG=3.23

# ---- build stage (dev variant: shell + Rust toolchain) ----
FROM ${RUST_IMAGE}:${RUST_TAG}-dev AS build
WORKDIR /src

# secp256k1 and keccak-asm compile native C/asm via the `cc` crate, so a C
# toolchain + musl headers must be present; keccak-asm's build script also
# shells out to perl to generate its assembly. DHI dev variants run as
# nonroot; switch to root only to install build tools, then build.
USER root
RUN apk add --no-cache musl-dev gcc make perl

# Copy manifests first, then sources (Cargo.lock is committed -> --locked).
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked --bin multichain-keygen

# ---- runtime stage (minimal hardened Alpine base, nonroot) ----
# Only the binary and its one dynamic dependency are copied in — no Rust
# toolchain in the final image. Rust's musl build links libgcc_s.so.1 (the
# unwinder) dynamically, so it is copied from the build stage rather than
# pulling a package into the runtime.
FROM ${RUNTIME_IMAGE}:${RUNTIME_TAG} AS runtime
COPY --from=build /usr/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1
COPY --from=build /src/target/release/multichain-keygen /usr/local/bin/multichain-keygen

# DHI images may set their own entrypoint; override it explicitly.
ENTRYPOINT ["multichain-keygen"]
CMD ["--help"]
