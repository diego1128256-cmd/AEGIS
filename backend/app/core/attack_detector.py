"""
Real-time attack detection middleware for Cayde-6.

Intercepts every HTTP request BEFORE routing. Double URL-decodes paths,
query params, and POST bodies to catch encoded injection payloads.
Auto-blocks IPs after 10 attacks in 5 minutes.
"""
import asyncio
import logging
import os
import re
import time
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Optional
from urllib.parse import unquote, unquote_plus

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logger = logging.getLogger("cayde6.attack_detector")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

BLOCKED_IPS_FILE = Path.home() / "Cayde-6" / "backend" / "blocked_ips.txt"
BLOCK_THRESHOLD = 10          # attacks before auto-block
BLOCK_WINDOW    = 300         # seconds (5 min)
RASPUTIN_URL    = os.getenv("AEGIS_FIREWALL_URL", "http://localhost:8000/api/rasputin")

# IPs that must NEVER be blocked — loaded from env var (comma-separated) or defaults
_safe_raw = os.getenv("AEGIS_SAFE_IPS", "127.0.0.1,::1,localhost")
SAFE_IPS = frozenset(ip.strip() for ip in _safe_raw.split(",") if ip.strip())

# ---------------------------------------------------------------------------
# Compiled regex attack patterns (run on double-decoded text)
# ---------------------------------------------------------------------------

ATTACK_PATTERNS: list[dict] = [
    # SQL Injection
    {
        "name": "sql_injection",
        "severity": "high",
        "regex": re.compile(
            r"(?i)"
            r"(union\s+(all\s+)?select"
            r"|or\s+1\s*=\s*1"
            r"|and\s+1\s*=\s*1"
            r"|'\s*or\s*'"
            r"|;\s*select\b"
            r"|;\s*drop\b"
            r"|;\s*insert\b"
            r"|;\s*update\b.*\bset\b"
            r"|;\s*delete\b"
            r"|information_schema"
            r"|sleep\s*\(\s*\d"
            r"|benchmark\s*\("
            r"|load_file\s*\("
            r"|into\s+outfile"
            r"|'\s*--"
            r"|'\s*#"
            r"|1'\s*or\s*'1'\s*=\s*'1"
            r"|admin'\s*--"
            r"|waitfor\s+delay"
            r"|extractvalue\s*\("
            r"|updatexml\s*\("
            r"|group_concat\s*\()"
        ),
    },
    # XSS
    {
        "name": "xss",
        "severity": "medium",
        "regex": re.compile(
            r"(?i)"
            r"(<script[\s>]"
            r"|javascript\s*:"
            r"|onerror\s*="
            r"|onload\s*="
            r"|onmouseover\s*="
            r"|onfocus\s*="
            r"|<img\s+[^>]*src\s*=\s*['\"]?x"
            r"|<svg[\s/+]"
            r"|<iframe"
            r"|document\.cookie"
            r"|document\.write"
            r"|eval\s*\("
            r"|alert\s*\("
            r"|prompt\s*\("
            r"|confirm\s*\()"
        ),
    },
    # Command Injection (before path_traversal — higher severity, avoids /etc/passwd overlap)
    {
        "name": "command_injection",
        "severity": "critical",
        "regex": re.compile(
            r"(?i)"
            r"(;\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh|python|perl|ruby)\b"
            r"|\|\s*(cat|ls|id|whoami|uname|wget|curl|nc|bash|sh)\b"
            r"|&&\s*(id|whoami|cat|ls)\b"
            r"|`[^`]*`"
            r"|\$\([^)]*\)"
            r"|\bexec\s*\("
            r"|\bsystem\s*\("
            r"|\bpassthru\s*\("
            r"|\bpopen\s*\()"
        ),
    },
    # Path Traversal
    {
        "name": "path_traversal",
        "severity": "high",
        "regex": re.compile(
            r"(\.\./|\.\.\\)"
            r"|(/etc/passwd"
            r"|/etc/shadow"
            r"|/proc/self"
            r"|/windows/system32"
            r"|/var/log"
            r"|\.htaccess"
            r"|\.htpasswd"
            r"|/web\.config"
            r"|wp-config\.php)"
        ),
    },
    # Scanner/Recon signatures
    {
        "name": "scanner",
        "severity": "low",
        "regex": re.compile(
            r"(?i)"
            r"(nmap|nikto|sqlmap|masscan|gobuster|dirbuster|wfuzz|nuclei|zgrab"
            r"|hydra|burpsuite|acunetix|nessus|openvas|arachni|w3af"
            r"|nmaplowercheck|/sdk|/evox|/HNAP1|/manager/html"
            r"|/solr/|/actuator|/wp-login|/xmlrpc\.php|/\.env"
            r"|/\.git/|/admin/config|/debug|/server-status|/server-info)"
        ),
    },
    # SSRF indicators
    {
        "name": "ssrf",
        "severity": "high",
        "regex": re.compile(
            r"(?i)"
            r"(http://169\.254\.169\.254"
            r"|http://metadata\.google"
            r"|http://100\.100\.100\.200"
            r"|http://localhost"
            r"|http://127\.0\.0\.1"
            r"|http://0\.0\.0\.0"
            r"|file:///)"
        ),
    },
]

SCANNER_USER_AGENTS = re.compile(
    r"(?i)(nmap|nikto|sqlmap|masscan|gobuster|dirbuster|wfuzz|nuclei|zgrab"
    r"|hydra|burpsuite|acunetix|nessus|openvas|arachni|python-requests"
    r"|go-http-client|curl/|libcurl|wget/|httpie|HTTrack|Scrapy"
    r"|DirBuster|Morfeus|ZmEu|w3af|Wfuzz|Nikto|sqlmap)"
)

# ---------------------------------------------------------------------------
# In-memory state
# ---------------------------------------------------------------------------

# Per-IP attack tracking: ip -> deque of (timestamp, pattern_name)
_attack_log: dict[str, deque] = defaultdict(deque)

# Blocked IPs (auto-blocked by this middleware)
_blocked_ips: set[str] = set()

# Stats
_stats = {
    "total_detections": 0,
    "total_blocks": 0,
    "detections_by_type": defaultdict(int),
}


def _load_blocked_ips():
    """Load blocked IPs from file on startup."""
    try:
        if BLOCKED_IPS_FILE.exists():
            for line in BLOCKED_IPS_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#"):
                    _blocked_ips.add(line)
            logger.info(f"[AttackDetector] Loaded {len(_blocked_ips)} blocked IPs from file")
    except Exception as e:
        logger.error(f"[AttackDetector] Failed to load blocked IPs: {e}")


# Load on import
_load_blocked_ips()


def _double_decode(text: str) -> str:
    """Double URL-decode to catch %25xx and +-as-space encoding tricks."""
    try:
        return unquote_plus(unquote_plus(text))
    except Exception:
        return text


def _get_client_ip(request: Request) -> str:
    """Extract real client IP from headers or connection."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def _check_patterns(text: str) -> Optional[dict]:
    """Check text against all attack patterns. Returns first match or None."""
    for pattern in ATTACK_PATTERNS:
        if pattern["regex"].search(text):
            return pattern
    return None


async def _block_ip(ip: str, reason: str):
    """Block an IP: add to memory set, append to file, notify Rasputin."""
    if ip in SAFE_IPS:
        logger.warning(f"[AttackDetector] Refusing to block safe IP {ip}")
        return

    _blocked_ips.add(ip)
    _stats["total_blocks"] += 1

    # Persist to file
    try:
        BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(BLOCKED_IPS_FILE, "a") as f:
            f.write(f"{ip}\n")
    except Exception as e:
        logger.error(f"[AttackDetector] Failed to write blocked IP to file: {e}")

    # Also update ip_blocker_service if available
    try:
        from app.core.ip_blocker import ip_blocker_service
        ip_blocker_service.block_ip(ip)
    except Exception:
        pass

    # Create incident in DB
    try:
        from app.database import async_session as _async_session
        from app.models.incident import Incident
        from app.models.client import Client
        from sqlalchemy import select

        async with _async_session() as db:
            result = await db.execute(select(Client).limit(1))
            client = result.scalar_one_or_none()
            if client:
                incident = Incident(
                    client_id=client.id,
                    title=f"CRITICAL: Auto-blocked IP {ip}",
                    description=(
                        f"IP {ip} was auto-blocked after exceeding "
                        f"{BLOCK_THRESHOLD} attacks in {BLOCK_WINDOW}s. "
                        f"Reason: {reason}"
                    ),
                    severity="critical",
                    status="open",
                    source="attack_detector",
                    source_ip=ip,
                    detected_at=datetime.utcnow(),
                )
                db.add(incident)
                await db.commit()
                logger.info(
                    f"[AttackDetector] Created CRITICAL incident for blocked IP {ip}"
                )
    except Exception as e:
        logger.error(f"[AttackDetector] Failed to create incident: {e}")

    # Notify Rasputin (best-effort)
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            await session.post(
                f"{RASPUTIN_URL}/block",
                json={
                    "ip": ip,
                    "reason": f"cayde6_auto_block: {reason}",
                    "duration": 3600,
                },
                timeout=aiohttp.ClientTimeout(total=3),
            )
            logger.info(f"[AttackDetector] Rasputin notified to block {ip}")
    except Exception as e:
        logger.debug(f"[AttackDetector] Rasputin block failed (non-fatal): {e}")

    logger.warning(f"[AttackDetector] AUTO-BLOCKED IP {ip} -- reason: {reason}")

    # Share to MongoDB aegis_threats collection
    try:
        from app.services.threat_intel_hub import threat_intel_hub
        await threat_intel_hub.share_ioc({
            "ioc_type": "ip",
            "ioc_value": ip,
            "threat_type": reason.split("(")[0].strip() if "(" in reason else reason,
            "confidence": 0.95,
            "detection_source": "attack_detector",
        })
        logger.info(f"[AttackDetector] Shared blocked IP {ip} to aegis_threats")
    except Exception as e:
        logger.debug(f"[AttackDetector] MongoDB share failed (non-fatal): {e}")


def _record_attack(ip: str, pattern_name: str) -> bool:
    """Record an attack. Returns True if IP should be blocked."""
    now = time.time()
    cutoff = now - BLOCK_WINDOW
    q = _attack_log[ip]
    # Prune old entries
    while q and q[0][0] < cutoff:
        q.popleft()
    q.append((now, pattern_name))

    _stats["total_detections"] += 1
    _stats["detections_by_type"][pattern_name] += 1

    return len(q) >= BLOCK_THRESHOLD


# ---------------------------------------------------------------------------
# Middleware
# ---------------------------------------------------------------------------

class AttackDetectorMiddleware(BaseHTTPMiddleware):
    """Real-time attack detection middleware.

    Runs BEFORE every request. Double URL-decodes path + query + body,
    matches against compiled attack patterns, auto-blocks repeat offenders.
    """

    async def dispatch(self, request: Request, call_next):
        client_ip = _get_client_ip(request)

        # 1. Check if already blocked
        if client_ip in _blocked_ips:
            return JSONResponse(
                status_code=403,
                content={"detail": "Access denied", "ip": client_ip},
            )

        # Skip safe IPs entirely
        if client_ip in SAFE_IPS:
            return await call_next(request)

        # 2. Collect text to scan
        texts_to_scan: list[str] = []

        # Path (double-decoded)
        raw_path = str(request.url)
        decoded_path = _double_decode(raw_path)
        texts_to_scan.append(decoded_path)

        # Query string
        qs = str(request.url.query) if request.url.query else ""
        if qs:
            decoded_qs = _double_decode(qs)
            texts_to_scan.append(decoded_qs)

        # User-Agent
        user_agent = request.headers.get("user-agent", "")
        if user_agent:
            texts_to_scan.append(user_agent)

        # POST body for mutation methods
        body_text = ""
        if request.method in ("POST", "PUT", "PATCH"):
            try:
                body_bytes = await request.body()
                if body_bytes and len(body_bytes) < 65536:  # max 64KB
                    body_text = body_bytes.decode("utf-8", errors="ignore")
                    decoded_body = _double_decode(body_text)
                    texts_to_scan.append(decoded_body)
            except Exception:
                pass

        # 2b. Brute force detection: rapid POST to auth endpoints
        auth_paths = ("/auth/login", "/auth/user/login", "/auth/token")
        if request.method == "POST" and any(p in request.url.path for p in auth_paths):
            now_ts = time.time()
            bf_key = f"bf:{client_ip}"
            bf_q = _attack_log.get(bf_key)
            if bf_q is None:
                bf_q = deque()
                _attack_log[bf_key] = bf_q
            cutoff = now_ts - 60  # 1 minute window
            while bf_q and bf_q[0][0] < cutoff:
                bf_q.popleft()
            bf_q.append((now_ts, "brute_force"))
            if len(bf_q) >= 5:  # 5 auth attempts in 1 min = brute force
                should_block = _record_attack(client_ip, "brute_force")
                logger.warning(
                    f"[DETECT] HIGH brute_force from {client_ip} "
                    f"path={request.url.path} attempts={len(bf_q)}"
                )
                if should_block:
                    await _block_ip(client_ip, f"brute_force ({len(bf_q)} attempts)")
                    return JSONResponse(
                        status_code=403,
                        content={"detail": "Access denied", "ip": client_ip},
                    )

        # 3. Check User-Agent for scanner signatures
        if user_agent and SCANNER_USER_AGENTS.search(user_agent):
            should_block = _record_attack(client_ip, "scanner")
            logger.warning(
                f"[DETECT] scanner UA from {client_ip}: {user_agent[:80]}"
            )
            if should_block:
                await _block_ip(
                    client_ip, f"scanner User-Agent: {user_agent[:60]}"
                )
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied", "ip": client_ip},
                )

        # 4a. Breadcrumb credential detection
        BREADCRUMB_INDICATORS = [
            "Tr4p_P4ssw0rd_2026",
            "AKIAIOSFODNN7BREADCRUMB",
            "sk-breadcrumb-trap-key",
            "sk_live_breadcrumb_trap",
            "breadcrumb-jwt-secret",
            "Tr4p_Adm1n_2026",
        ]
        check_text = " ".join(texts_to_scan)
        attacks_found: list[tuple[str, str]] = []
        for crumb in BREADCRUMB_INDICATORS:
            if crumb in check_text:
                attacks_found.append(("breadcrumb_credential_used", "critical"))
                break

        if attacks_found:
            attack_name, severity = attacks_found[0]
            should_block = _record_attack(client_ip, attack_name)
            logger.critical(
                f"[DETECT] BREADCRUMB credential used by {client_ip} "
                f"path={request.url.path} method={request.method}"
            )
            if should_block:
                await _block_ip(client_ip, f"{attack_name} ({severity})")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied", "ip": client_ip},
                )

        # 4. Pattern matching on all collected text
        combined = " ".join(texts_to_scan)
        match = _check_patterns(combined)
        if match:
            should_block = _record_attack(client_ip, match["name"])
            severity = match["severity"]
            name = match["name"]

            logger.warning(
                f"[DETECT] {severity.upper()} {name} from {client_ip} "
                f"path={request.url.path} method={request.method}"
            )

            if should_block:
                await _block_ip(client_ip, f"{name} ({severity})")
                return JSONResponse(
                    status_code=403,
                    content={"detail": "Access denied", "ip": client_ip},
                )

        # 5. Continue to next middleware / route handler
        return await call_next(request)


# ---------------------------------------------------------------------------
# Public API for admin endpoints
# ---------------------------------------------------------------------------

def get_blocked_ips() -> list[str]:
    """Return sorted list of all blocked IPs."""
    return sorted(_blocked_ips)


def unblock_ip(ip: str) -> bool:
    """Remove an IP from the blocked set. Returns True if it was blocked."""
    was_blocked = ip in _blocked_ips
    _blocked_ips.discard(ip)
    # Also remove from ip_blocker_service
    try:
        from app.core.ip_blocker import ip_blocker_service
        ip_blocker_service.unblock_ip(ip)
    except Exception:
        pass
    # Rewrite file without this IP
    try:
        if BLOCKED_IPS_FILE.exists():
            lines = BLOCKED_IPS_FILE.read_text().splitlines()
            filtered = [l for l in lines if l.strip() != ip]
            BLOCKED_IPS_FILE.write_text("\n".join(filtered) + "\n")
    except Exception:
        pass
    return was_blocked


def get_stats() -> dict:
    """Return detection statistics."""
    return {
        "total_detections": _stats["total_detections"],
        "total_blocks": _stats["total_blocks"],
        "blocked_ips_count": len(_blocked_ips),
        "detections_by_type": dict(_stats["detections_by_type"]),
    }
