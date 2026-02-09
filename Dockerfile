# CoreVPN Docker Image
# Multi-stage build with hardened Debian slim runtime
# Uses ECR Public Gallery images to avoid Docker Hub rate limits
#
# Note: Alpine/musl cannot build proc-macros on aarch64, so we use
# Debian-based images for full architecture support (amd64 + arm64).

# =============================================================================
# Build stage - using Rust on Debian for full proc-macro support
# =============================================================================
FROM public.ecr.aws/docker/library/rust:bookworm AS builder

WORKDIR /build

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    pkg-config \
    libssl-dev \
    make \
    perl \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests
COPY Cargo.toml Cargo.lock ./

# Copy crates (excluding corevpn-ui which depends on local openkit)
COPY crates/corevpn-crypto ./crates/corevpn-crypto
COPY crates/corevpn-core ./crates/corevpn-core
COPY crates/corevpn-protocol ./crates/corevpn-protocol
COPY crates/corevpn-auth ./crates/corevpn-auth
COPY crates/corevpn-config ./crates/corevpn-config
COPY crates/corevpn-server ./crates/corevpn-server
COPY crates/corevpn-cli ./crates/corevpn-cli

# Remove workspace members not needed for server build
# corevpn-ui depends on local openkit, corevpn-nm depends on system D-Bus libs
RUN sed -i '/"crates\/corevpn-ui"/d; /"crates\/corevpn-nm"/d' Cargo.toml

# Build release binaries
RUN cargo build --release -p corevpn-server -p corevpn-cli \
    && strip target/release/corevpn-server \
    && strip target/release/corevpn

# =============================================================================
# Runtime stage - Hardened Debian slim
# =============================================================================
FROM public.ecr.aws/docker/library/debian:bookworm-slim

# Labels for container metadata
LABEL org.opencontainers.image.title="CoreVPN Server" \
      org.opencontainers.image.description="Secure OpenVPN-compatible VPN server with OAuth2 support" \
      org.opencontainers.image.vendor="Pegasus Heavy Industries" \
      org.opencontainers.image.source="https://github.com/PegasusHeavyIndustries/corevpn" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Security: Run security updates and install minimal runtime dependencies
RUN apt-get update \
    && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
        # TLS/crypto runtime
        libssl3 \
        ca-certificates \
        # Networking tools for VPN (iptables includes ip6tables on Debian)
        iproute2 \
        iptables \
        # Process management
        tini \
        # Process tools for healthcheck
        procps \
    # Create directories
    && mkdir -p /var/lib/corevpn /var/log/corevpn /etc/corevpn /run/corevpn \
    # Clean up
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
              /tmp/* \
              /usr/share/man \
              /usr/share/doc

# Create non-root user with specific UID/GID for consistency
RUN groupadd -g 1000 corevpn \
    && useradd -u 1000 -g corevpn -d /var/lib/corevpn -s /usr/sbin/nologin corevpn

# Copy binaries from builder
COPY --from=builder /build/target/release/corevpn-server /usr/bin/
COPY --from=builder /build/target/release/corevpn /usr/bin/corevpn-cli

# Copy default config
COPY packaging/config/config.toml.example /etc/corevpn/config.toml.example

# Set ownership and permissions
RUN chown -R corevpn:corevpn /var/lib/corevpn /var/log/corevpn /run/corevpn \
    && chmod 750 /var/lib/corevpn /var/log/corevpn /run/corevpn \
    && chmod 755 /usr/bin/corevpn-server /usr/bin/corevpn-cli

# Security hardening
# - No shell for corevpn user (already set above)
# - Remove setuid/setgid bits from all files
RUN find / -xdev -perm /6000 -type f -exec chmod a-s {} \; 2>/dev/null || true

# Expose ports
EXPOSE 1194/udp 443/tcp 8080/tcp

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -x corevpn-server > /dev/null || exit 1

# Use tini as init system to handle signals properly
ENTRYPOINT ["/usr/bin/tini", "--", "corevpn-server"]
CMD ["run", "--config", "/etc/corevpn/config.toml"]
