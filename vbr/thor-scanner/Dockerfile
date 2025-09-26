FROM debian:stable-slim
RUN set -eux; \
   apt-get update; \
   apt-get install -y --no-install-recommends ca-certificates; \
   rm -rf /var/lib/apt/lists/*
WORKDIR /thor
COPY . /thor/
RUN chmod +x /thor/thor-lite-linux-64
ENTRYPOINT ["/thor/thor-lite-linux-64"]
