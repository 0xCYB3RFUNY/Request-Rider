FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install --no-install-recommends --yes tor \
    && rm -rf /var/lib/apt/lists/*

COPY torrc /etc/tor/torrc
RUN mkdir -p /var/lib/tor \
    && chown -R debian-tor:debian-tor /var/lib/tor

USER debian-tor
EXPOSE 9050
CMD ["tor", "-f", "/etc/tor/torrc"]
