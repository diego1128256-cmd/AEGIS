#!/usr/bin/env python3
"""
AEGIS Autonomous Defense Platform - Interactive Setup Wizard

Run after install.sh to configure:
  - AI provider (OpenRouter / OpenAI / Ollama)
  - Network detection and asset discovery
  - Notification preferences
  - Admin user creation

Usage:
    python3 scripts/setup-wizard.py
    python3 scripts/setup-wizard.py --non-interactive  # Use defaults
"""

import json
import os
import secrets
import socket
import subprocess
import sys
import time
from pathlib import Path

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

CYAN = "\033[0;36m"
GREEN = "\033[0;32m"
YELLOW = "\033[1;33m"
RED = "\033[0;31m"
BOLD = "\033[1m"
NC = "\033[0m"


def log(msg: str) -> None:
    print(f"{GREEN}[+]{NC} {msg}")


def warn(msg: str) -> None:
    print(f"{YELLOW}[!]{NC} {msg}")


def error(msg: str) -> None:
    print(f"{RED}[x]{NC} {msg}")


def info(msg: str) -> None:
    print(f"{CYAN}[*]{NC} {msg}")


def ask(prompt: str, default: str = "") -> str:
    suffix = f" [{default}]" if default else ""
    answer = input(f"  {prompt}{suffix}: ").strip()
    return answer if answer else default


def ask_yes_no(prompt: str, default: bool = True) -> bool:
    suffix = "[Y/n]" if default else "[y/N]"
    answer = input(f"  {prompt} {suffix}: ").strip().lower()
    if not answer:
        return default
    return answer in ("y", "yes")


def banner() -> None:
    print(f"""
{CYAN}{BOLD}  AEGIS Setup Wizard
  ====================={NC}
  Configure your defense platform interactively.
""")


# ---------------------------------------------------------------------------
# Network Detection
# ---------------------------------------------------------------------------

def get_local_ip() -> str:
    """Get the primary local IP address."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return "127.0.0.1"


def detect_interfaces() -> list[dict]:
    """Detect network interfaces and their IP ranges."""
    interfaces = []
    try:
        result = subprocess.run(
            ["ip", "-j", "addr", "show"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            for iface in json.loads(result.stdout):
                name = iface.get("ifname", "")
                if name == "lo":
                    continue
                for addr_info in iface.get("addr_info", []):
                    if addr_info.get("family") == "inet":
                        ip = addr_info["local"]
                        prefix = addr_info.get("prefixlen", 24)
                        interfaces.append({
                            "name": name,
                            "ip": ip,
                            "cidr": f"{ip}/{prefix}",
                        })
            return interfaces
    except (FileNotFoundError, subprocess.TimeoutExpired, json.JSONDecodeError):
        pass

    # macOS / fallback
    try:
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, timeout=5,
        )
        if result.returncode == 0:
            current_iface = ""
            for line in result.stdout.splitlines():
                if not line.startswith(("\t", " ")):
                    current_iface = line.split(":")[0]
                elif "inet " in line and "127.0.0.1" not in line:
                    parts = line.strip().split()
                    ip_idx = parts.index("inet") + 1
                    ip = parts[ip_idx]
                    interfaces.append({
                        "name": current_iface,
                        "ip": ip,
                        "cidr": f"{ip}/24",
                    })
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    if not interfaces:
        local_ip = get_local_ip()
        interfaces.append({
            "name": "default",
            "ip": local_ip,
            "cidr": f"{local_ip}/24",
        })

    return interfaces


def quick_scan_network(cidr: str) -> list[dict]:
    """Run a quick ping sweep using nmap if available."""
    hosts = []
    try:
        result = subprocess.run(
            ["nmap", "-sn", "-T4", cidr, "--open"],
            capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0:
            current_ip = ""
            for line in result.stdout.splitlines():
                if "Nmap scan report for" in line:
                    parts = line.split()
                    current_ip = parts[-1].strip("()")
                elif "Host is up" in line and current_ip:
                    hosts.append({"ip": current_ip, "status": "up"})
    except (FileNotFoundError, subprocess.TimeoutExpired):
        warn("nmap not found or scan timed out. Skipping network discovery.")
    return hosts


# ---------------------------------------------------------------------------
# Configuration Steps
# ---------------------------------------------------------------------------

def step_ai_provider() -> dict:
    """Configure AI provider."""
    print(f"\n{BOLD}Step 1: AI Provider{NC}")
    print("  AEGIS uses an LLM for threat analysis and response planning.")
    print("  Supported providers:")
    print("    1. OpenRouter (recommended - free models available)")
    print("    2. OpenAI")
    print("    3. Ollama (local, no API key needed)")
    print("    4. Skip (configure later)")
    print()

    choice = ask("Select provider", "1")
    config = {}

    if choice == "1":
        key = ask("OpenRouter API key (sk-or-v1-...)")
        if key:
            config["OPENROUTER_API_KEY"] = key
            config["OPENROUTER_BASE_URL"] = "https://openrouter.ai/api/v1"
        else:
            warn("No key provided. You can set OPENROUTER_API_KEY in .env later.")

    elif choice == "2":
        key = ask("OpenAI API key (sk-...)")
        if key:
            config["OPENROUTER_API_KEY"] = key
            config["OPENROUTER_BASE_URL"] = "https://api.openai.com/v1"

    elif choice == "3":
        ollama_url = ask("Ollama base URL", "http://host.docker.internal:11434/v1")
        config["OPENROUTER_API_KEY"] = "ollama"
        config["OPENROUTER_BASE_URL"] = ollama_url
        info("Ollama configured. Make sure Ollama is running on the host.")

    else:
        info("Skipping AI provider. Set OPENROUTER_API_KEY in .env when ready.")

    return config


def step_network() -> dict:
    """Detect and configure network settings."""
    print(f"\n{BOLD}Step 2: Network Detection{NC}")
    config = {}

    interfaces = detect_interfaces()
    if interfaces:
        log(f"Detected {len(interfaces)} network interface(s):")
        for iface in interfaces:
            print(f"    {iface['name']}: {iface['cidr']}")
    else:
        warn("No network interfaces detected.")

    local_ip = get_local_ip()
    info(f"Primary IP: {local_ip}")

    # Ask about API URL for external access
    external_url = ask("External API URL (for clients outside Docker)", f"http://{local_ip}:8000/api/v1")
    config["NEXT_PUBLIC_API_URL"] = external_url
    config["NEXT_PUBLIC_WS_URL"] = external_url.replace("http://", "ws://").replace("https://", "wss://").replace("/api/v1", "/ws")

    return config


def step_scan_network() -> list[dict]:
    """Optionally scan local network for assets."""
    print(f"\n{BOLD}Step 3: Asset Discovery{NC}")

    if not ask_yes_no("Scan local network for hosts?", default=True):
        info("Skipping network scan.")
        return []

    local_ip = get_local_ip()
    cidr = ask("Network range to scan", f"{local_ip}/24")

    info(f"Scanning {cidr} (this may take 30-60 seconds)...")
    hosts = quick_scan_network(cidr)

    if hosts:
        log(f"Found {len(hosts)} live host(s):")
        for h in hosts[:20]:  # Show first 20
            print(f"    {h['ip']}")
        if len(hosts) > 20:
            print(f"    ... and {len(hosts) - 20} more")
    else:
        warn("No hosts found (nmap may not be installed on the host).")
        info("Hosts will be discovered when scanning from inside the AEGIS container.")

    return hosts


def step_notifications() -> dict:
    """Configure notification preferences."""
    print(f"\n{BOLD}Step 4: Notifications{NC}")
    config = {}

    if ask_yes_no("Configure webhook notifications?", default=False):
        url = ask("Webhook URL (Slack/Discord/Teams)")
        if url:
            config["WEBHOOK_URL"] = url

    if ask_yes_no("Configure email notifications?", default=False):
        config["SMTP_HOST"] = ask("SMTP host", "smtp.gmail.com")
        config["SMTP_PORT"] = ask("SMTP port", "587")
        config["SMTP_USER"] = ask("SMTP user/email")
        config["SMTP_PASS"] = ask("SMTP password")

    if not config:
        info("No notifications configured. You can add them to .env later.")

    return config


def step_admin() -> dict:
    """Create admin credentials."""
    print(f"\n{BOLD}Step 5: Admin Account{NC}")
    config = {}

    admin_pass = ask("Admin password (min 8 chars)", "")
    if admin_pass and len(admin_pass) >= 8:
        config["ADMIN_PASSWORD"] = admin_pass
    else:
        generated = secrets.token_urlsafe(12)
        config["ADMIN_PASSWORD"] = generated
        log(f"Generated admin password: {generated}")
        warn("Save this password. It will not be shown again.")

    return config


# ---------------------------------------------------------------------------
# Write Configuration
# ---------------------------------------------------------------------------

def update_env_file(updates: dict, env_path: str = ".env") -> None:
    """Update .env file with new values, preserving existing keys."""
    env_file = Path(env_path)
    lines = []
    existing_keys = set()

    if env_file.exists():
        for line in env_file.read_text().splitlines():
            stripped = line.strip()
            if stripped and not stripped.startswith("#") and "=" in stripped:
                key = stripped.split("=", 1)[0]
                if key in updates:
                    lines.append(f"{key}={updates[key]}")
                    existing_keys.add(key)
                else:
                    lines.append(line)
            else:
                lines.append(line)

    # Append new keys not already in the file
    new_keys = set(updates.keys()) - existing_keys
    if new_keys:
        lines.append("")
        lines.append("# Added by setup-wizard")
        for key in sorted(new_keys):
            lines.append(f"{key}={updates[key]}")

    env_file.write_text("\n".join(lines) + "\n")
    log(f"Updated {env_path}")


def register_assets_via_api(hosts: list[dict]) -> None:
    """Register discovered assets with the AEGIS API."""
    if not hosts:
        return

    info("Registering discovered assets with AEGIS API...")
    api_url = "http://localhost:8000/api/v1"

    try:
        import urllib.request

        for host in hosts[:50]:  # Limit to 50 assets
            payload = json.dumps({
                "ip": host["ip"],
                "hostname": host.get("hostname", ""),
                "type": "host",
                "source": "setup-wizard",
            }).encode()

            req = urllib.request.Request(
                f"{api_url}/surface/assets",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                urllib.request.urlopen(req, timeout=5)
            except Exception:
                pass  # API might not have this endpoint yet

        log(f"Registered {min(len(hosts), 50)} assets.")
    except Exception as e:
        warn(f"Could not register assets: {e}")


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    banner()

    # Determine working directory (project root)
    script_dir = Path(__file__).resolve().parent
    project_root = script_dir.parent
    os.chdir(project_root)
    info(f"Working directory: {project_root}")

    non_interactive = "--non-interactive" in sys.argv

    all_config = {}

    if non_interactive:
        info("Running in non-interactive mode with defaults.")
        all_config["AEGIS_ENV"] = "production"
        all_config["AEGIS_SECRET_KEY"] = secrets.token_hex(32)
    else:
        # Step 1: AI Provider
        all_config.update(step_ai_provider())

        # Step 2: Network
        all_config.update(step_network())

        # Step 3: Asset Discovery
        hosts = step_scan_network()

        # Step 4: Notifications
        all_config.update(step_notifications())

        # Step 5: Admin
        admin_config = step_admin()
        all_config.update(admin_config)

    # Write .env
    print(f"\n{BOLD}Applying Configuration{NC}")
    update_env_file(all_config)

    # Register assets if API is running
    if not non_interactive and hosts:
        register_assets_via_api(hosts)

    # Summary
    print(f"""
{GREEN}{BOLD}============================================================{NC}
{GREEN}{BOLD}  Setup Complete{NC}
{GREEN}{BOLD}============================================================{NC}

  Restart services to apply changes:
    docker compose restart

  Then open: http://localhost:3000

  Admin credentials:
    Username: admin
    Password: {all_config.get('ADMIN_PASSWORD', '(check .env)')}

""")


if __name__ == "__main__":
    main()
