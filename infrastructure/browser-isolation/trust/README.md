# Isolated-browser private-CA trust

`chromium-policy.json` here (generated, git-ignored) is mounted read-only at
`/etc/securepam/trust` and is the only way a non-public CA becomes trusted by the
isolated browser. Generate it with `../trust_policy.py`; every CA is limited to the
exact host names / narrow IP ranges you pass. No file = public CAs only.

Chromium reads it as the managed policy `CACertificatesWithConstraints`; `daemon.py`
reads the same file for its pre-flight TLS check. Certificates are always validated
(chain, validity, host name); a registered SPKI pin is checked in addition.
