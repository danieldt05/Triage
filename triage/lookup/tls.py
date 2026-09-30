"""TLS certificate observation. Two handshakes: one verified (did it pass, and
OpenSSL's reason if not), one unverified (so a broken certificate can still be
read). Both send SNI, otherwise shared hosts and CDNs return the wrong cert."""

from __future__ import annotations

import socket
import ssl

from cryptography import x509
from cryptography.x509.oid import ExtensionOID, NameOID

from triage.lookup.target import address_class
from triage.model import CertInfo, TLSResult

PORT = 443
TIMEOUT = 6.0

# OpenSSL X509_V_ERR_* codes used by the rules.
ERR_NOT_YET_VALID = 9
ERR_EXPIRED = 10
ERR_SELF_SIGNED_LEAF = 18
ERR_SELF_SIGNED_IN_CHAIN = 19
ERR_NO_LOCAL_ISSUER = 20
ERR_CANT_VERIFY_LEAF = 21
ERR_HOSTNAME_MISMATCH = 62


def observe(host: str) -> TLSResult:
    result = TLSResult(host=host)
    kind = address_class(host)
    if kind != "public":
        result.error = "The name doesn't resolve." if kind == "unresolvable" else "Host resolves to a private address; not checked."
        return result
    try:
        _verified_handshake(host, result)
        _read_certificate(host, result)
    except socket.gaierror:
        result.error = "The name doesn't resolve."
    except ConnectionRefusedError:
        result.error = "Nothing is listening on port 443 (no HTTPS)."
    except TimeoutError:
        result.error = f"Timed out after {TIMEOUT:g} s."
    except ssl.SSLError as e:
        result.error = f"TLS handshake failed: {e.reason or e}"
    except OSError as e:
        result.error = f"Connection failed: {e.strerror or e}"
    return result


def _verified_handshake(host: str, result: TLSResult) -> None:
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, PORT), timeout=TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                result.verified = True
                result.version = ssock.version()
    except ssl.SSLCertVerificationError as e:
        result.verified = False
        result.verify_code = e.verify_code
        result.verify_message = e.verify_message


def _read_certificate(host: str, result: TLSResult) -> None:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, PORT), timeout=TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as ssock:
            der = ssock.getpeercert(binary_form=True)  # getpeercert() is {} with CERT_NONE
            result.version = result.version or ssock.version()
            get_chain = getattr(ssock, "get_unverified_chain", None)  # Python 3.13+
            if get_chain:
                try:
                    result.chain_length = len(get_chain() or [])
                except (ssl.SSLError, ValueError):
                    pass
    if der:
        result.cert = parse_cert(der)


def parse_cert(der: bytes) -> CertInfo:
    cert = x509.load_der_x509_certificate(der)

    def attr(name: x509.Name, oid) -> str | None:
        values = name.get_attributes_for_oid(oid)
        return str(values[0].value) if values else None

    try:
        san = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        sans = []
    issuer_org = attr(cert.issuer, NameOID.ORGANIZATION_NAME)
    issuer_cn = attr(cert.issuer, NameOID.COMMON_NAME)
    issuer = " / ".join(x for x in (issuer_org, issuer_cn) if x) or None
    return CertInfo(
        subject_cn=attr(cert.subject, NameOID.COMMON_NAME),
        issuer=issuer,
        sans=sans,
        not_before=cert.not_valid_before_utc,
        not_after=cert.not_valid_after_utc,
        self_signed=cert.issuer == cert.subject,
    )
