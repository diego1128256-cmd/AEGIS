"""Auto-discovery engine for AEGIS setup wizard.

Wraps nmap to discover hosts and services on a target IP or CIDR range,
identifies service types from port/banner data, estimates risk, and
suggests hostnames.
"""

import asyncio
import logging
import re
import shutil
import time
from dataclasses import dataclass, field
from typing import Optional

from app.config import settings

logger = logging.getLogger("aegis.auto_discovery")


# ---------------------------------------------------------------------------
# Service-identification tables
# ---------------------------------------------------------------------------

PORT_SERVICE_MAP: dict[int, tuple[str, str]] = {
    # port -> (asset_type, friendly_name)
    21: ("server", "FTP"),
    22: ("server", "SSH"),
    23: ("server", "Telnet"),
    25: ("server", "SMTP"),
    53: ("server", "DNS"),
    80: ("web_application", "HTTP"),
    110: ("server", "POP3"),
    143: ("server", "IMAP"),
    443: ("web_application", "HTTPS"),
    445: ("server", "SMB"),
    993: ("server", "IMAPS"),
    995: ("server", "POP3S"),
    1433: ("database", "MSSQL"),
    1521: ("database", "Oracle DB"),
    2375: ("server", "Docker API"),
    2376: ("server", "Docker API (TLS)"),
    3000: ("web_application", "Web App"),
    3001: ("web_application", "Web App"),
    3006: ("web_application", "Web App"),
    3306: ("database", "MySQL"),
    3389: ("server", "RDP"),
    5432: ("database", "PostgreSQL"),
    5672: ("server", "RabbitMQ"),
    5900: ("server", "VNC"),
    6379: ("cache", "Redis"),
    8000: ("api_server", "API Server"),
    8080: ("api_server", "API Server"),
    8443: ("web_application", "HTTPS Alt"),
    8888: ("web_application", "Web App"),
    9090: ("web_application", "Web Admin"),
    9200: ("database", "Elasticsearch"),
    9300: ("database", "Elasticsearch Transport"),
    11211: ("cache", "Memcached"),
    11434: ("ai_service", "Ollama"),
    15672: ("server", "RabbitMQ Management"),
    27017: ("database", "MongoDB"),
}

# Ports in these ranges default to web_application
WEB_PORT_RANGES = [(3000, 3999), (8000, 8999)]

# Services considered high-risk when exposed
HIGH_RISK_SERVICES = {
    "database", "cache", "ai_service",
}

# Specific high-risk ports (common attack targets)
HIGH_RISK_PORTS = {21, 23, 445, 2375, 3389, 5900}

# Banner substrings -> technology name
BANNER_TECH_MAP: list[tuple[str, str]] = [
    ("next.js", "Next.js"),
    ("nextjs", "Next.js"),
    ("express", "Express"),
    ("nginx", "Nginx"),
    ("apache", "Apache"),
    ("node", "Node.js"),
    ("python", "Python"),
    ("uvicorn", "Uvicorn"),
    ("fastapi", "FastAPI"),
    ("gunicorn", "Gunicorn"),
    ("openresty", "OpenResty"),
    ("caddy", "Caddy"),
    ("traefik", "Traefik"),
    ("postgresql", "PostgreSQL"),
    ("mysql", "MySQL"),
    ("mariadb", "MariaDB"),
    ("mongodb", "MongoDB"),
    ("redis", "Redis"),
    ("openssh", "OpenSSH"),
    ("dropbear", "Dropbear SSH"),
    ("ollama", "Ollama"),
    ("docker", "Docker"),
    ("microsoft", "Microsoft"),
]


@dataclass
class DiscoveredService:
    port: int
    protocol: str  # tcp / udp
    state: str  # open / filtered / closed
    service: str  # nmap service name
    version: str  # nmap version string
    hostname: str
    asset_type: str
    risk_estimate: int  # 0-100
    technologies: list[str] = field(default_factory=list)


@dataclass
class HostResult:
    ip: str
    hostname: str
    os_guess: str
    services: list[DiscoveredService] = field(default_factory=list)


@dataclass
class ScanResult:
    target: str
    scan_time_ms: int
    hosts: list[HostResult] = field(default_factory=list)
    error: Optional[str] = None


class AutoDiscovery:
    """Discovers hosts and services using nmap."""

    def __init__(self):
        self._nmap_path: Optional[str] = None

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def find_nmap(self) -> Optional[str]:
        """Locate the nmap binary.  Checks config, common paths, then PATH."""
        if self._nmap_path:
            return self._nmap_path

        candidates = [
            settings.NMAP_PATH,
            "/usr/local/bin/nmap",
            "/usr/bin/nmap",
            "/opt/homebrew/bin/nmap",
        ]
        for path in candidates:
            if shutil.which(path):
                self._nmap_path = path
                return path

        # Fallback: search PATH
        found = shutil.which("nmap")
        if found:
            self._nmap_path = found
        return found

    async def discover_host(self, ip: str) -> ScanResult:
        """Run an nmap service scan against a single host."""
        return await self._run_nmap(ip)

    async def discover_network(self, cidr: str) -> ScanResult:
        """Run an nmap service scan against a CIDR range."""
        return await self._run_nmap(cidr)

    def identify_service(self, port: int, banner: str) -> tuple[str, str]:
        """Map port + banner to (asset_type, friendly_name).

        Returns a tuple of (asset_type, service_name).
        """
        # Check exact port map first
        if port in PORT_SERVICE_MAP:
            asset_type, name = PORT_SERVICE_MAP[port]
        else:
            # Check web port ranges
            asset_type, name = "server", "Unknown"
            for lo, hi in WEB_PORT_RANGES:
                if lo <= port <= hi:
                    asset_type, name = "web_application", "Web App"
                    break

        # Override name with banner info when available
        if banner:
            banner_lower = banner.lower()
            for substr, tech_name in BANNER_TECH_MAP:
                if substr in banner_lower:
                    name = tech_name
                    break

        return asset_type, name

    def suggest_hostname(self, ip: str, port: int, service: str) -> str:
        """Generate a hostname suggestion based on IP, port, and service."""
        # Use service name as base
        base = service.lower().replace(" ", "-")
        # Strip special chars
        base = re.sub(r"[^a-z0-9\-]", "", base)
        if not base:
            base = "host"

        # Use last octet of IP for uniqueness
        octet = ip.split(".")[-1] if "." in ip else ip[-4:]
        return f"{base}-{octet}"

    def estimate_risk(self, service: str, port: int, version: str) -> int:
        """Estimate risk score (0-100) based on service type and exposure.

        Factors:
        - Service type (database exposed = very high risk)
        - Port (known-dangerous ports)
        - Version info (outdated = higher risk)
        - Common defaults (e.g., port 22 with old SSH)
        """
        score = 30  # baseline for any open port

        # Service-type risk
        asset_type, _ = self.identify_service(port, version)
        if asset_type in HIGH_RISK_SERVICES:
            score += 40
        elif asset_type == "api_server":
            score += 15
        elif asset_type == "web_application":
            score += 10

        # Dangerous-port bonus
        if port in HIGH_RISK_PORTS:
            score += 20

        # Version-based heuristics
        if version:
            v_lower = version.lower()
            # Old/known-vulnerable indicators
            if any(kw in v_lower for kw in ("outdated", "eol", "1.x", "2.x")):
                score += 10
            # No version info at all can mean something weird
        else:
            score += 5  # Unknown version is slightly suspicious

        return min(score, 100)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    async def _run_nmap(self, target: str) -> ScanResult:
        """Execute nmap and parse the output."""
        nmap_bin = self.find_nmap()
        if not nmap_bin:
            return ScanResult(
                target=target,
                scan_time_ms=0,
                error="nmap not found. Install with: brew install nmap (macOS) or apt install nmap (Linux)",
            )

        cmd = [
            nmap_bin,
            "-sV",        # service/version detection
            "-T4",        # aggressive timing
            "--top-ports", "100",
            "-oG", "-",   # greppable output to stdout
            target,
        ]

        logger.info(f"Running nmap: {' '.join(cmd)}")
        start = time.monotonic()

        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=300)
            elapsed_ms = int((time.monotonic() - start) * 1000)
        except asyncio.TimeoutError:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ScanResult(target=target, scan_time_ms=elapsed_ms, error="nmap timed out after 300s")
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return ScanResult(target=target, scan_time_ms=elapsed_ms, error=str(exc))

        output = stdout.decode(errors="replace")
        err_output = stderr.decode(errors="replace")

        if proc.returncode != 0 and not output.strip():
            return ScanResult(
                target=target,
                scan_time_ms=elapsed_ms,
                error=f"nmap exited with code {proc.returncode}: {err_output[:500]}",
            )

        hosts = self._parse_greppable(output)
        return ScanResult(target=target, scan_time_ms=elapsed_ms, hosts=hosts)

    def _parse_greppable(self, output: str) -> list[HostResult]:
        """Parse nmap greppable (-oG -) output."""
        hosts: list[HostResult] = []
        # Pattern: Host: <ip> (<hostname>)\tPorts: <port>/<state>/<proto>//<service>//<version>/, ...
        host_pattern = re.compile(
            r"^Host:\s+(\S+)\s+\(([^)]*)\).*Ports:\s+(.+)",
            re.MULTILINE,
        )

        for match in host_pattern.finditer(output):
            ip = match.group(1)
            hostname = match.group(2) or ""
            ports_str = match.group(3)

            services: list[DiscoveredService] = []
            # Each port entry: port/state/protocol//service_name//version/
            port_entries = ports_str.split(",")
            for entry in port_entries:
                entry = entry.strip()
                if not entry:
                    continue
                parts = entry.split("/")
                if len(parts) < 7:
                    continue

                port_num = int(parts[0].strip()) if parts[0].strip().isdigit() else 0
                state = parts[1].strip()
                protocol = parts[2].strip()
                service_name = parts[4].strip() if len(parts) > 4 else ""
                version_str = parts[6].strip() if len(parts) > 6 else ""

                if state != "open":
                    continue

                asset_type, friendly = self.identify_service(port_num, f"{service_name} {version_str}")
                risk = self.estimate_risk(friendly, port_num, version_str)
                svc_hostname = hostname or self.suggest_hostname(ip, port_num, friendly)

                # Detect technologies from banner
                techs: list[str] = []
                combined = f"{service_name} {version_str}".lower()
                for substr, tech_name in BANNER_TECH_MAP:
                    if substr in combined:
                        techs.append(tech_name)

                services.append(DiscoveredService(
                    port=port_num,
                    protocol=protocol,
                    state=state,
                    service=friendly,
                    version=version_str,
                    hostname=svc_hostname,
                    asset_type=asset_type,
                    risk_estimate=risk,
                    technologies=techs,
                ))

            if services:
                os_guess = ""
                # Try to extract OS from the Status/OS line
                os_match = re.search(rf"Host:\s+{re.escape(ip)}.*OS:\s+(.+?)(?:\t|$)", output)
                if os_match:
                    os_guess = os_match.group(1).strip()

                hosts.append(HostResult(
                    ip=ip,
                    hostname=hostname or (services[0].hostname if services else ""),
                    os_guess=os_guess,
                    services=services,
                ))

        return hosts


# Singleton
auto_discovery = AutoDiscovery()
