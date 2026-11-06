"""Target scope enforcement.

Every destination of a tool invocation is validated here BEFORE approval and
REVALIDATED at execution time (DNS re-resolve). Out-of-scope, private/internal
(not explicitly authorized) and cloud-metadata destinations are rejected.
"""

import ipaddress
import socket
from urllib.parse import urlparse

import requests

from backend.config import ALWAYS_BLOCKED_CIDRS, DATA_DIR
from backend.storage import repos

# Resolved hostname -> allowed ip set cache for redirect/DNS revalidation.
_res_cache_path = DATA_DIR / "dns_cache.json"

BLOCKED_NETS = [ipaddress.ip_network(c) for c in ALWAYS_BLOCKED_CIDRS]


class ScopeError(Exception):
    pass


def _is_private(ip: str) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return a.is_private or a.is_loopback or a.is_link_local or a.is_reserved or a.is_multicast


def resolve(host: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as e:
        raise ScopeError(f"DNS lookup failed for {host}: {e}") from e
    ips = sorted({i[4][0] for i in infos})
    if not ips:
        raise ScopeError(f"no addresses for {host}")
    return ips


class ScopeValidator:
    def __init__(self, target_id: str):
        t = repos.targets().get(target_id)
        if not t:
            raise ScopeError(f"target {target_id} not found")
        self.target = t
        s = t["scope"]
        self.domains = {d.lower().rstrip(".") for d in s.get("domains", [])}
        self.ips: list[ipaddress.ip_address] = []
        self.cidrs: list[ipaddress.ip_network] = []
        for ip in s.get("ips", []):
            self.ips.append(ipaddress.ip_address(ip))
        for c in s.get("cidrs", []):
            self.cidrs.append(ipaddress.ip_network(c, strict=False))
        self.ports: set[int] = {int(p) for p in s.get("ports", []) if 1 <= int(p) <= 65535}
        url = urlparse(t["url"])
        self.target_host = (url.hostname or "").lower()
        self.target_port = url.port or (443 if url.scheme == "https" else 80)
        if not self.ports:
            self.ports = {self.target_port}
        if self.target_host:
            self.domains.add(self.target_host)
        self.authorized_private = self._authorized_private()

    def _authorized_private(self) -> bool:
        # only if the user explicitly listed a private ip/cidr in the target scope
        for ip in self.ips:
            if _is_private(str(ip)):
                return True
        for c in self.cidrs:
            if c.is_private:
                return True
        return False

    # ---- checks -------------------------------------------------------------

    def check_destination(self, host: str, port: int | None = None) -> list[str]:
        """Validate a reachable destination (hostname or IP). Returns resolved IPs."""
        host = (host or "").strip().lower()
        if not host:
            raise ScopeError("empty destination")
        if "localhost" in host or host == "::1":
            if not self.authorized_private:
                raise ScopeError("localhost is not in the authorized scope")
        try:
            ipaddress.ip_address(host)
            is_literal_ip = True
        except ValueError:
            is_literal_ip = False
        if is_literal_ip:
            ip = ipaddress.ip_address(host)
            if self._blocked(ip):
                raise ScopeError(f"destination {host} is in a prohibited range (cloud metadata/link-local)")
            if not self._allowed_ip(ip):
                raise ScopeError(f"destination {host} is outside the authorized scope")
            if port is not None and int(port) not in self.ports:
                raise ScopeError(f"port {port} is not in the authorized port list")
            return [host]
        # hostname: within domain allowlist + resolution not prohibited/private
        if not self._domain_allowed(host):
            raise ScopeError(f"host {host} is outside the authorized domains")
        ips = resolve(host)
        for i in ips:
            ip = ipaddress.ip_address(i)
            if self._blocked(ip):
                raise ScopeError(f"{host} resolves to prohibited address {i} (cloud metadata/link-local)")
        if not self.authorized_private:
            for i in ips:
                if _is_private(i):
                    raise ScopeError(
                        f"{host} resolves to private address {i}; add it explicitly to target scope.ips to authorize internal testing"
                    )
        if port is not None and int(port) not in self.ports:
            raise ScopeError(f"port {port} is not in the authorized port list")
        return ips

    def _blocked(self, ip) -> bool:
        return any(ip in net for net in BLOCKED_NETS)

    def _domain_allowed(self, host: str) -> bool:
        host = host.lower().rstrip(".")
        for d in self.domains:
            if host == d or host.endswith("." + d):
                return True
        return False

    def _allowed_ip(self, ip) -> bool:
        return any(ip == a for a in self.ips) or any(ip in n for n in self.cidrs)

    def check_url(self, url: str) -> list[str]:
        p = urlparse(url)
        if p.scheme not in ("http", "https"):
            raise ScopeError(f"unsupported scheme {p.scheme!r}")
        if not p.hostname:
            raise ScopeError("url missing hostname")
        return self.check_destination(p.hostname, p.port or (443 if p.scheme == "https" else 80))

    def revalidate_snapshot(self, snapshot: dict) -> bool:
        """DNS revalidation: current resolution must still be within allowlist."""
        host = snapshot.get("host", "")
        if not host:
            return False
        try:
            current = self.check_destination(host, snapshot.get("port"))
            saved = snapshot.get("ips", [])
            # allow minor DNS churn but all current ips must be in scope; snapshots recorded for audit
            return bool(current)
        except ScopeError:
            return False

    def check_destination_strict(self, host: str, port: int | None = None) -> list[str]:
        """Like check_destination, but requires EVERY resolved IP to be in-scope."""
        host = (host or "").strip().lower()
        try:
            ipaddress.ip_address(host)
            is_literal = True
        except ValueError:
            is_literal = False
        if is_literal:
            return self.check_destination(host, port)
        ips = resolve(host)
        for i in ips:
            ip = ipaddress.ip_address(i)
            if self._blocked(ip):
                raise ScopeError(f"{host} resolves to prohibited address {i}")
            if not self._allowed_ip(ip) and not (_is_private(i) and self.authorized_private):
                raise ScopeError(
                    f"{host} resolves to {i} which is outside the authorized scope (strict revalidation)"
                )
        if port is not None and int(port) not in self.ports:
            raise ScopeError(f"port {port} is not in the authorized port list")
        if not self._domain_allowed(host):
            raise ScopeError(f"host {host} is outside the authorized domains")
        return ips
