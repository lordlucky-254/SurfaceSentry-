import ssl
import socket
from datetime import datetime
from typing import Dict, Any, Optional

class TLSInspector:
    """
    Connects via SSL/TLS to retrieve certificate details and check validity/expiration.
    """

    def inspect(self, host: str, port: int = 443, timeout: float = 3.0) -> Optional[Dict[str, Any]]:
        context = ssl.create_default_context()
        # For security assessment, do not fail on hostname mismatch or self-signed certs
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    # If CERT_NONE is used, getpeercert() returns empty dict, so retrieve DER cert
                    der_cert = ssock.getpeercert(binary_form=True)

            # Re-parse or extract expiration with ssl cert if available
            # We can also attempt a standard verified handshake or parse DER if cert is empty
            if not cert:
                v_ctx = ssl.create_default_context()
                try:
                    with socket.create_connection((host, port), timeout=timeout) as s:
                        with v_ctx.wrap_socket(s, server_hostname=host) as v_ssock:
                            cert = v_ssock.getpeercert()
                except Exception:
                    pass

            if not cert:
                return None

            # Parse subject and expiration
            subject_parts = [val[0][1] for val in cert.get("subject", []) if val]
            subject = "/".join(subject_parts) if subject_parts else host

            not_after_str = cert.get("notAfter")
            days_left = None
            if not_after_str:
                # SSL date format: 'May 20 12:00:00 2025 GMT'
                try:
                    exp_date = datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                    delta = exp_date - datetime.utcnow()
                    days_left = delta.days
                except Exception:
                    pass

            san_entries = []
            for item in cert.get("subjectAltName", []):
                if item[0].lower() == "dns":
                    san_entries.append(item[1])

            return {
                "subject": subject,
                "expiry": not_after_str,
                "days_left": days_left,
                "sans": san_entries
            }
        except Exception:
            return None
