FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        tor \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /var/lib/tor \
    && chown -R debian-tor:debian-tor /var/lib/tor

COPY torrc /etc/tor/torrc

RUN chown debian-tor:debian-tor /etc/tor/torrc \
    && chmod 600 /etc/tor/torrc

USER debian-tor

HEALTHCHECK \
    --interval=30s \
    --timeout=15s \
    --start-period=30s \
    --retries=5 \
    CMD curl \
        --fail \
        --silent \
        --show-error \
        --socks5-hostname 127.0.0.1:9050 \
        https://check.torproject.org/api/ip \
        > /dev/null || exit 1

CMD ["tor", "-f", "/etc/tor/torrc"]