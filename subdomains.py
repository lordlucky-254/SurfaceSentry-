import asyncio
import json
import re
import socket
import urllib.request
from typing import Set, List, Tuple

DEFAULT_SUBDOMAINS = [
    "www", "mail", "api", "dev", "staging", "test", "app", "admin", 
    "portal", "auth", "login", "vpn", "cdn", "status", "docs", "blog",
    "git", "corp", "internal", "secure", "monitor", "beta"
]

class SubdomainEnumerator:
    def __init__(self, concurrency: int = 50, timeout: float = 3.0):
        self.concurrency = concurrency
        self.timeout = timeout

    async def enumerate(self, domain: str, use_crtsh: bool = True) -> Set[str]:
        candidates: Set[str] = {domain}

        # 1. Add common subdomains
        for sub in DEFAULT_SUBDOMAINS:
            candidates.add(f"{sub}.{domain}")

        # 2. Passive recon via crt.sh Certificate Transparency logs
        if use_crtsh:
            passive_subs = await asyncio.to_thread(self._fetch_crtsh, domain)
            candidates.update(passive_subs)

        # 3. Resolve candidates concurrently to filter out nonexistent domains
        resolved = await self._resolve_candidates(candidates)
        return resolved

    def _fetch_crtsh(self, domain: str) -> Set[str]:
        found: Set[str] = set()
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        try:
            req = urllib.request.Request(
                url,
                headers={"User-Agent": "SurfaceSentry-Security-Scanner/1.0"}
            )
            with urllib.request.urlopen(req, timeout=6.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                for item in data:
                    name_value = item.get("name_value", "")
                    for name in name_value.split("\n"):
                        name = name.strip().lower()
                        # Clean wildcard prefixes
                        if name.startswith("*."):
                            name = name[2:]
                        if name.endswith(domain) and " " not in name:
                            found.add(name)
        except Exception:
            # Fall back gracefully if crt.sh is unreachable or rate limited
            pass
        return found

    async def _resolve_single(self, subdomain: str, sem: asyncio.Semaphore) -> Tuple[str, bool, List[str]]:
        async with sem:
            loop = asyncio.get_running_loop()
            try:
                # Resolve IPv4/IPv6 asynchronously via thread pool
                addr_info = await asyncio.wait_for(
                    loop.run_in_executor(None, socket.getaddrinfo, subdomain, None),
                    timeout=self.timeout
                )
                ips = list({res[4][0] for res in addr_info if res and len(res) > 4})
                return (subdomain, True, ips)
            except Exception:
                return (subdomain, False, [])

    async def _resolve_candidates(self, candidates: Set[str]) -> Set[str]:
        sem = asyncio.Semaphore(self.concurrency)
        tasks = [self._resolve_single(sub, sem) for sub in candidates]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        valid_subdomains: Set[str] = set()
        for res in results:
            if isinstance(res, tuple) and res[1]:
                valid_subdomains.add(res[0])
        return valid_subdomains
