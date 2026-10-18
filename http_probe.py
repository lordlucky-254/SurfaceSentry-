import re
import urllib.request
import ssl
from typing import Dict, Any, List

TECH_SIGNATURES = {
    "Nginx": [r"nginx", r"Server:.*nginx"],
    "Apache": [r"apache", r"Server:.*apache"],
    "Cloudflare": [r"cloudflare", r"cf-ray", r"server:.*cloudflare"],
    "Amazon CloudFront": [r"cloudfront", r"x-amz-cf-id"],
    "WordPress": [r"wp-content", r"wp-includes"],
    "Express / Node.js": [r"x-powered-by:.*express"],
    "PHP": [r"x-powered-by:.*php"],
    "ASP.NET": [r"x-powered-by:.*asp\.net", r"x-aspnet-version"],
    "Django": [r"csrftoken", r"x-frame-options: SAMEORIGIN"],
    "OpenSSH": [r"OpenSSH"],
}

class HTTPProber:
    def __init__(self, timeout: float = 3.0):
        self.timeout = timeout
        self.ssl_context = ssl.create_default_context()
        self.ssl_context.check_hostname = False
        self.ssl_context.verify_mode = ssl.CERT_NONE

    def probe(self, host: str, port: int) -> Dict[str, Any]:
        proto = "https" if port in (443, 8443) else "http"
        url = f"{proto}://{host}:{port}/"
        res = {
            "url": url,
            "status": None,
            "title": None,
            "server": None,
            "headers": {},
            "technologies": []
        }

        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/5.0 (compatible; SurfaceSentry/1.0)"}
            )
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ssl_context) as resp:
                res["status"] = resp.status
                headers = dict(resp.headers)
                res["headers"] = headers
                res["server"] = headers.get("Server") or headers.get("server")

                body = resp.read(8192).decode("utf-8", errors="ignore")
                
                # Extract title
                title_match = re.search(r"<title>(.*?)</title>", body, re.IGNORECASE)
                if title_match:
                    res["title"] = title_match.group(1).strip()[:80]

                # Fingerprint technologies
                combined_content = f"{str(headers)} {body}"
                for tech, patterns in TECH_SIGNATURES.items():
                    for pattern in patterns:
                        if re.search(pattern, combined_content, re.IGNORECASE):
                            if tech not in res["technologies"]:
                                res["technologies"].append(tech)
                            break
        except urllib.error.HTTPError as e:
            res["status"] = e.code
            res["server"] = e.headers.get("Server") or e.headers.get("server")
        except Exception:
            pass

        return res
