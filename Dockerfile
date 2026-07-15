# syntax=docker/dockerfile:1.7

ARG RUST_VERSION=1.97.0

# ---- chef: rust toolchain + cargo-chef, cached as its own layer ----
FROM rust:${RUST_VERSION}-slim-trixie AS chef
WORKDIR /app
RUN cargo install --locked cargo-chef@0.1.77

# ---- planner: figure out the dependency "recipe" ----
FROM chef AS planner
COPY . .
RUN cargo chef prepare --recipe-path recipe.json

# ---- builder: cook deps (cached layer), then build the real binary ----
FROM chef AS builder
COPY --from=planner /app/recipe.json recipe.json
RUN cargo chef cook --release --recipe-path recipe.json
COPY . .
RUN cargo build --release --bin disposable-domain-verifier

# ---- runtime: distroless, debian 13 (trixie), non-root, no toolchain ----
FROM gcr.io/distroless/cc-debian13:nonroot AS runtime
WORKDIR /app
COPY --from=builder /app/assets ./assets
COPY --from=builder /app/target/release/disposable-domain-verifier ./disposable-domain-verifier
USER nonroot:nonroot
ENTRYPOINT ["./disposable-domain-verifier"]
