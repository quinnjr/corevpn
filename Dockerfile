# CoreVPN Docker Image
# Multi-stage build with hardened Alpine runtime
# Uses ECR Public Gallery images to avoid Docker Hub rate limits

# =============================================================================
# Build stage - using Rust with musl for static linking
# =============================================================================
FROM public.ecr.aws/docker/library/rust:alpine AS builder

WORKDIR /build

# Install build dependencies for musl static compilation
RUN apk add --no-cache \
    musl-dev \
    openssl-dev \
    openssl-libs-static \
    pkgconf \
    make \
    perl

# Set environment for static linking (musl defaults to +crt-static)
ENV RUSTFLAGS="-C target-feature=+crt-static"
ENV OPENSSL_STATIC=1
ENV OPENSSL_LIB_DIR=/usr/lib
ENV OPENSSL_INCLUDE_DIR=/usr/include

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

# Remove corevpn-ui from workspace members (it depends on local openkit)
RUN sed -i '/"crates\/corevpn-ui"/d' Cargo.toml

# Build release binaries
RUN cargo build --release -p corevpn-server -p corevpn-cli \
    && strip target/release/corevpn-server \
    && strip target/release/corevpn

# =============================================================================
# Runtime stage - Hardened Alpine
# =============================================================================
FROM public.ecr.aws/docker/library/alpine:3.23

# Labels for container metadata
LABEL org.opencontainers.image.title="CoreVPN Server" \
      org.opencontainers.image.description="Secure OpenVPN-compatible VPN server with OAuth2 support" \
      org.opencontainers.image.vendor="Pegasus Heavy Industries" \
      org.opencontainers.image.source="https://github.com/PegasusHeavyIndustries/corevpn" \
      org.opencontainers.image.licenses="MIT OR Apache-2.0"

# Security: Run security updates and install minimal runtime dependencies
RUN apk upgrade --no-cache \
    && apk add --no-cache \
        # TLS/crypto runtime
        libssl3 \
        libcrypto3 \
        ca-certificates \
        # Networking tools for VPN
        iproute2 \
        iptables \
        ip6tables \
        # Process management
        tini \
        # Minimal shell for healthchecks
        busybox \
    # Create directories
    && mkdir -p /var/lib/corevpn /var/log/corevpn /etc/corevpn /run/corevpn \
    # Remove unnecessary files to reduce attack surface
    && rm -rf /var/cache/apk/* \
              /tmp/* \
              /usr/share/man \
              /usr/share/doc

# Create non-root user with specific UID/GID for consistency
RUN addgroup -g 1000 -S corevpn \
    && adduser -u 1000 -S -G corevpn -h /var/lib/corevpn -s /sbin/nologin corevpn

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

# Health check using busybox pgrep
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD pgrep -x corevpn-server > /dev/null || exit 1

# Use tini as init system to handle signals properly
ENTRYPOINT ["/sbin/tini", "--", "corevpn-server"]
CMD ["run", "--config", "/etc/corevpn/config.toml"]
