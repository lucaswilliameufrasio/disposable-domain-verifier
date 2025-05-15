FROM lukemathwalker/cargo-chef:latest-rust-1.86.0-alpine AS chef

# Create and change to the app directory.
WORKDIR /app

FROM chef AS planner
COPY . ./
RUN cargo chef prepare --recipe-path recipe.json

FROM chef AS builder 
COPY --from=planner /app/recipe.json recipe.json

# Build dependencies - this is the caching Docker layer!
RUN cargo chef cook --release --recipe-path recipe.json

# Build application
COPY . ./
RUN cargo build --release

FROM builder as runner

COPY --from=builder /app/assets assets
COPY --from=builder /app/target/release/disposable-domain-verifier ./bin/disposable-domain-verifier
COPY --from=builder /app/recipe.json recipe.json

CMD ["./bin/disposable-domain-verifier"]