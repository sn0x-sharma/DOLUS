# Multi-stage build for minimal final image
FROM gcc:13 AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssh-dev libsqlite3-dev libjson-c-dev libcurl4-openssl-dev uuid-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY src/ src/
COPY Makefile .
COPY dolus.conf.example .

RUN make DEBUG=0

# Final stage - minimal runtime image
FROM debian:12-slim AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssh-4 libsqlite3-0 libjson-c5 libcurl4 libuuid1 ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd -r dolus --gid 999 \
    && useradd -r -g dolus --uid 999 --home-dir /var/lib/dolus --shell /bin/false dolus

COPY --from=builder /build/bin/dolus /usr/local/bin/dolus
COPY --from=builder /build/dolus.conf.example /etc/dolus/dolus.conf.example

RUN mkdir -p /etc/dolus /var/lib/dolus /var/log/dolus /var/run/dolus \
    && chown -R dolus:dolus /etc/dolus /var/lib/dolus /var/log/dolus /var/run/dolus

USER dolus

VOLUME ["/var/lib/dolus", "/var/log/dolus", "/etc/dolus"]

EXPOSE 2222 8080 9090

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD dolus --config /etc/dolus/dolus.conf status || exit 1

ENTRYPOINT ["dolus"]
CMD ["--config", "/etc/dolus/dolus.conf", "start"]