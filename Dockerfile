# First stage: Build the Rust project
FROM rustlang/rust:nightly AS builder

# Set the working directory inside the container
WORKDIR /usr/src/myapp

# Copy the current directory contents into the container at /usr/src/myapp
COPY . .

# Build the Rust project
RUN cargo build --release

# Second stage: Create a lightweight runtime image
FROM debian:buster-slim

# Set the working directory inside the container
WORKDIR /usr/src/myapp

# Copy the compiled binary from the builder stage
COPY --from=builder /usr/src/myapp/target/release/myapp .

# Run the compiled binary
CMD ["./myapp"]
