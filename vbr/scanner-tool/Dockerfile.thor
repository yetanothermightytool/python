FROM debian:stable-slim

# Pass the binary filename at build time, e.g.:
#   docker build --build-arg THOR_BIN=thor-linux-64 -t thor .
ARG THOR_BIN=thor-lite-linux-64

RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /thor
COPY . /thor/
RUN chmod +x /thor/${THOR_BIN}

ENV THOR_BIN=${THOR_BIN}
ENTRYPOINT ["/bin/sh", "-c", "exec /thor/$THOR_BIN \"$@\"", "--"]
