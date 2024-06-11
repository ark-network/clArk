# Stage 1: Building the code
FROM rust:1.78 as builder

WORKDIR /usr/src

# Install protobuf-compiler and libclang
RUN apt-get update && apt-get install -y protobuf-compiler clang libclang-dev && rm -rf /var/lib/apt/lists/*

# Copy over your manifests and source code
COPY . . 

# Build for release. 
RUN cargo build --release

# Stage 2: Setup the runtime environment
FROM debian:buster-slim

# Install necessary runtime dependencies
RUN apt-get update && apt-get install -y libssl-dev ca-certificates && rm -rf /var/lib/apt/lists/*

# Copy the binary from the builder stage
COPY --from=builder /usr/src/target/release/arkd /usr/local/bin/arkd
COPY --from=builder /usr/src/target/release/noah /usr/local/bin/noah

# Set the data directory and give write permissions
RUN mkdir /data && chown -R nobody:nogroup /data
VOLUME ["/data"]

# Expose the necessary ports
EXPOSE 35035 3536

# Switch to a non-root user
USER nobody

# Set the startup command to run your binary
CMD ["arkd"]