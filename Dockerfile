# syntax=docker/dockerfile:1

# Docker Hardened Images. `dhi.io/rust` requires your org's DHI entitlement.
# Override RUST_IMAGE to a mirrored namespace (e.g. <org>/dhi-rust) if needed.
# Verify the exact available tag in the DHI Rust catalog before building —
# the dev variant adds the `-dev` suffix (e.g. `1-alpine` -> `1-alpine-dev`).
ARG RUST_IMAGE=dhi.io/rust
ARG RUST_TAG=1-alpine

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

# ---- runtime stage (non-dev variant: hardened, nonroot) ----
# The Rust runtime variant keeps a shell + toolchain, so this image is ~650MB.
# The binary is a fully static musl ELF (~1.8MB), so for a much smaller,
# shell-less, toolchain-less runtime you can swap this FROM for the DHI `static`
# image once your org has it entitled — confirm the exact tag in the catalog,
# e.g.  FROM dhi.io/static:<tag>  (Alpine/musl static variant). Nothing else changes.
FROM ${RUST_IMAGE}:${RUST_TAG} AS runtime
COPY --from=build /src/target/release/multichain-keygen /usr/local/bin/multichain-keygen

# DHI images may set their own entrypoint; override it explicitly.
ENTRYPOINT ["multichain-keygen"]
CMD ["--help"]
