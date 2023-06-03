FROM alpine as builder
RUN apk add --allow-untrusted --update --no-cache curl ca-certificates
WORKDIR /
RUN curl -fsSL github.com/sipcapture/rtcagent/releases/latest/download/rtcagent -O && chmod +x rtcagent

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /rtcagent /rtcagent
CMD ["/rtcagent"]
