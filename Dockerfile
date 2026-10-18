# syntax=docker/dockerfile:1

# Builder stage: download the released static binary. The optional
# RTCAGENT_SHA256 build arg lets CI/users verify the downloaded artifact.
FROM alpine:3.20 AS builder

ARG RTCAGENT_VERSION=latest
ARG RTCAGENT_SHA256=""

RUN apk add --no-cache curl ca-certificates

WORKDIR /out
RUN curl -fsSL "https://github.com/sipcapture/rtcagent/releases/${RTCAGENT_VERSION}/download/rtcagent" -o rtcagent \
    && if [ -n "${RTCAGENT_SHA256}" ]; then echo "${RTCAGENT_SHA256}  rtcagent" | sha256sum -c -; fi \
    && chmod +x rtcagent

FROM scratch

LABEL org.opencontainers.image.title="rtcagent" \
      org.opencontainers.image.description="eBPF powered HEP capture agent for VoIP/WebRTC" \
      org.opencontainers.image.source="https://github.com/sipcapture/rtcagent" \
      org.opencontainers.image.url="https://github.com/sipcapture/rtcagent" \
      org.opencontainers.image.licenses="AGPL-3.0"

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /out/rtcagent /rtcagent

# ENTRYPOINT (instead of CMD) lets users pass the rtcagent sub-command and
# flags directly, e.g. `docker run --privileged <image> kamailio -m /usr/sbin/kamailio`.
ENTRYPOINT ["/rtcagent"]