"""
Write the isolated browser's private-CA trust policy (operator tool; runs on the host).

    python3 trust_policy.py --ca wazuh-root-ca.pem --permit-dns wazuh.example.internal \
        [--permit-ip 3.104.196.100] [--out trust/chromium-policy.json]

The output is a Chromium managed policy (CACertificatesWithConstraints). compose.yml mounts trust/
read-only into the container, where Chromium loads it as a managed policy and daemon.py's pre-flight
TLS check reads the same file, so both trust the same CA for the same names only.

What it refuses, so a mistake cannot silently widen trust:
  - a certificate that is not a CA (basicConstraints CA:TRUE), or is expired / not yet valid;
  - no name constraint at all, or an over-broad one (a single DNS label such as "com", a wildcard,
    or an IP range wider than /24 for IPv4 or /64 for IPv6).

This never disables verification: certificates are still checked for chain, validity and name, and
the application's SPKI pin (if registered) is still enforced on top. A CA certificate is public
information; the CA's PRIVATE key must never be placed here or anywhere near this container.
"""

import argparse
import base64
import hashlib
import ipaddress
import json
import os
import sys
from datetime import datetime, timezone


def load_ca_certs(pem_path: str):
    from cryptography import x509
    with open(pem_path, "rb") as f:
        data = f.read()
    if b"PRIVATE KEY" in data:
        raise SystemExit("refusing: the file contains a PRIVATE KEY. Provide the CA certificate only.")
    certs = x509.load_pem_x509_certificates(data)
    now = datetime.now(timezone.utc)
    for c in certs:
        try:
            bc = c.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            bc = None
        if not (bc and bc.ca):
            raise SystemExit(f"refusing: {c.subject.rfc4514_string()} is not a CA certificate (basicConstraints CA:TRUE)")
        if not (c.not_valid_before_utc <= now <= c.not_valid_after_utc):
            raise SystemExit(f"refusing: {c.subject.rfc4514_string()} is expired or not yet valid")
    return certs


def check_constraints(dns_names, cidrs):
    if not dns_names and not cidrs:
        raise SystemExit("refusing: at least one --permit-dns or --permit-ip is required (no unconstrained CA trust)")
    out_dns, out_cidrs = [], []
    for d in dns_names:
        d = d.strip().lower().rstrip(".")
        if "*" in d or "." not in d or not all(part for part in d.split(".")):
            raise SystemExit(f"refusing: {d!r} is too broad or malformed (use the exact host name)")
        out_dns.append(d)
    for c in cidrs:
        net = ipaddress.ip_network(c.strip(), strict=False)
        if net.prefixlen < (24 if net.version == 4 else 64):
            raise SystemExit(f"refusing: {net} is wider than allowed (/24 IPv4, /64 IPv6)")
        out_cidrs.append(str(net))
    return out_dns, out_cidrs


def build_policy(certs, dns_names, cidrs) -> dict:
    from cryptography.hazmat.primitives import serialization
    return {"CACertificatesWithConstraints": [
        {"certificate": base64.b64encode(c.public_bytes(serialization.Encoding.DER)).decode(),
         "constraints": {"permitted_dns_names": dns_names, "permitted_cidrs": cidrs}}
        for c in certs]}


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--ca", required=True, help="PEM file with the private root (and optional intermediate) CA cert(s)")
    ap.add_argument("--permit-dns", action="append", default=[], help="exact host name the CA may vouch for")
    ap.add_argument("--permit-ip", action="append", default=[], help="IP or narrow CIDR the CA may vouch for")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "trust", "chromium-policy.json"))
    args = ap.parse_args(argv)

    certs = load_ca_certs(args.ca)
    dns_names, cidrs = check_constraints(args.permit_dns, args.permit_ip)
    policy = build_policy(certs, dns_names, cidrs)
    os.makedirs(os.path.dirname(args.out), exist_ok=True)
    tmp = args.out + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)
    os.chmod(tmp, 0o644)  # public CA certs only; the non-root container user must read it
    os.replace(tmp, args.out)
    from cryptography.hazmat.primitives import serialization
    for c in certs:
        fp = hashlib.sha256(c.public_bytes(serialization.Encoding.DER)).hexdigest()
        print(f"trusted CA {c.subject.rfc4514_string()} sha256={fp}")
    print(f"limited to dns={dns_names} ip={cidrs}")
    print(f"wrote {args.out}. Recreate the container to apply: docker compose up -d --force-recreate")
    return 0


if __name__ == "__main__":
    sys.exit(main())
