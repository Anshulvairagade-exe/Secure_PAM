# SecurePAM isolated browser: one Xvfb display + Chromium + x11vnc + egress proxy per session.
# The container is the isolation boundary (non-root, read-only root fs, no capabilities, tmpfs for all
# per-session state). See README.md for why Chromium's own sandbox is not available here.
FROM alpine:3.20
RUN apk add --no-cache chromium xvfb x11vnc python3 py3-cryptography ca-certificates font-noto ttf-dejavu \
 && adduser -D -u 1000 browser \
 && mkdir -p /etc/chromium/policies/managed /etc/securepam/trust \
 && ln -s /etc/securepam/trust/chromium-policy.json /etc/chromium/policies/managed/securepam-trust.json
COPY policies.json /etc/chromium/policies/managed/securepam.json
COPY daemon.py /app/daemon.py
USER 1000
WORKDIR /app
EXPOSE 6090
CMD ["python3", "/app/daemon.py"]
