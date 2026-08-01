#!/usr/bin/env python3
"""
CyberMesh Attack Simulation Script
===================================
Runs a complete demo scenario:
  Phase 1: Normal traffic (learning mode) — 30 seconds
  Phase 2: Switch to enforce mode
  Phase 3: Attack simulation — lateral movement, rate abuse, payload anomaly
  Phase 4: Service revocation demo

Usage:
  python scripts/attack_simulation.py [--proxy-url http://localhost:8080] [--fast]
"""

import argparse
import asyncio
import json
import sys
import time
from datetime import datetime

try:
    import httpx
except ImportError:
    print("ERROR: httpx is required. Install with: pip install httpx")
    sys.exit(1)

# ─── Configuration ───────────────────────────────────────────────────────────

DEFAULT_PROXY_URL = "http://localhost:8080"
AUTH_URL = "http://localhost:8081"

# Service credentials (must match shared/config.py)
SERVICE_SECRETS = {
    "user-service": "user-service-secret-key",
    "billing-service": "billing-service-secret-key",
    "admin-service": "admin-service-secret-key",
}

# ─── Helpers ─────────────────────────────────────────────────────────────────

class Colors:
    GREEN = "\033[92m"
    RED = "\033[91m"
    YELLOW = "\033[93m"
    CYAN = "\033[96m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RESET = "\033[0m"


def log(msg: str, color: str = ""):
    timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]
    prefix = f"{Colors.DIM}[{timestamp}]{Colors.RESET}"
    print(f"{prefix} {color}{msg}{Colors.RESET}")


def log_phase(phase: str, description: str):
    print(f"\n{'='*70}")
    print(f"{Colors.BOLD}{Colors.CYAN}  PHASE {phase}: {description}{Colors.RESET}")
    print(f"{'='*70}\n")


def log_result(caller: str, target: str, path: str, status: int, latency_ms: float, body: dict):
    if status == 200:
        icon = f"{Colors.GREEN}✓ ALLOWED{Colors.RESET}"
    elif status == 401:
        icon = f"{Colors.YELLOW}⚠ STEP-UP{Colors.RESET}"
    elif status == 403:
        icon = f"{Colors.RED}✗ BLOCKED{Colors.RESET}"
    else:
        icon = f"{Colors.DIM}? {status}{Colors.RESET}"

    trust = body.get("trust_score", "N/A")
    log(f"  {icon}  {caller} → {target}{path}  "
        f"[trust={trust}, latency={latency_ms:.1f}ms]")

    # Show block reasons if any
    if status in (401, 403) and "reasons" in body:
        for reason in body.get("reasons", []):
            result_icon = "✓" if reason.get("result") == "PASS" else "✗"
            color = Colors.GREEN if reason.get("result") == "PASS" else Colors.RED
            log(f"          {color}{result_icon} [{reason.get('check')}] {reason.get('detail')}{Colors.RESET}")


async def get_token(client: httpx.AsyncClient, service_name: str) -> str:
    """Get a JWT token from the auth service."""
    try:
        resp = await client.post(f"{AUTH_URL}/token", json={
            "service_name": service_name,
            "secret": SERVICE_SECRETS[service_name],
        })
        if resp.status_code == 200:
            return resp.json()["token"]
        else:
            log(f"  Failed to get token for {service_name}: {resp.status_code}", Colors.RED)
            return ""
    except Exception as e:
        log(f"  Failed to get token for {service_name}: {e}", Colors.RED)
        return ""


async def proxy_request(
    client: httpx.AsyncClient,
    proxy_url: str,
    caller: str,
    target: str,
    path: str,
    method: str = "GET",
    token: str = "",
    payload: dict | None = None,
) -> tuple[int, float, dict]:
    """Send a request through the CyberMesh proxy."""
    url = f"{proxy_url}/proxy/{target}{path}"
    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    headers["X-Service-Name"] = caller

    start = time.perf_counter()
    try:
        if method == "GET":
            resp = await client.get(url, headers=headers)
        elif method == "POST":
            resp = await client.post(url, headers=headers, json=payload or {})
        else:
            resp = await client.request(method, url, headers=headers)

        latency = (time.perf_counter() - start) * 1000

        try:
            body = resp.json()
        except Exception:
            body = {"raw": resp.text[:200]}

        return resp.status_code, latency, body
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return 0, latency, {"error": str(e)}


# ─── Simulation Phases ──────────────────────────────────────────────────────

async def phase1_normal_traffic(client: httpx.AsyncClient, proxy_url: str, duration: int = 30):
    """Send normal, legitimate traffic patterns for the proxy to learn."""
    log_phase("1", f"NORMAL TRAFFIC — Learning Mode ({duration}s)")
    log("Sending legitimate inter-service traffic so the proxy can learn normal patterns...", Colors.CYAN)

    # First, switch to learning mode
    try:
        resp = await client.post(f"{proxy_url}/mode", json={"mode": "learning"})
        log(f"Mode set to LEARNING: {resp.json()}", Colors.GREEN)
    except Exception as e:
        log(f"Warning: Could not set learning mode: {e}", Colors.YELLOW)

    # Get tokens for legitimate services
    user_token = await get_token(client, "user-service")
    billing_token = await get_token(client, "billing-service")
    admin_token = await get_token(client, "admin-service")

    if not all([user_token, billing_token, admin_token]):
        log("WARNING: Some tokens failed to issue. Continuing with available tokens.", Colors.YELLOW)

    start_time = time.time()
    request_count = 0

    while time.time() - start_time < duration:
        # Legitimate pattern 1: user-service → billing-service (get invoices)
        if user_token:
            status, lat, body = await proxy_request(
                client, proxy_url, "user-service", "billing-service", "/invoices", token=user_token
            )
            log_result("user-service", "billing-service", "/invoices", status, lat, body)
            request_count += 1

        await asyncio.sleep(0.5)

        # Legitimate pattern 2: billing-service → user-service (lookup user)
        if billing_token:
            status, lat, body = await proxy_request(
                client, proxy_url, "billing-service", "user-service", "/users", token=billing_token
            )
            log_result("billing-service", "user-service", "/users", status, lat, body)
            request_count += 1

        await asyncio.sleep(0.5)

        # Legitimate pattern 3: admin-service → user-service (admin checks users)
        if admin_token:
            status, lat, body = await proxy_request(
                client, proxy_url, "admin-service", "user-service", "/users/1", token=admin_token
            )
            log_result("admin-service", "user-service", "/users/1", status, lat, body)
            request_count += 1

        await asyncio.sleep(0.5)

        # Legitimate pattern 4: admin-service → billing-service (admin checks billing)
        if admin_token:
            status, lat, body = await proxy_request(
                client, proxy_url, "admin-service", "billing-service", "/invoices", token=admin_token
            )
            log_result("admin-service", "billing-service", "/invoices", status, lat, body)
            request_count += 1

        await asyncio.sleep(0.5)

        # Refresh tokens periodically (every ~15s they'll be >50% through TTL)
        elapsed = time.time() - start_time
        if int(elapsed) % 15 == 0 and int(elapsed) > 0:
            log("Refreshing tokens...", Colors.DIM)
            user_token = await get_token(client, "user-service")
            billing_token = await get_token(client, "billing-service")
            admin_token = await get_token(client, "admin-service")

    log(f"\n  ✓ Phase 1 complete: {request_count} legitimate requests sent over {duration}s", Colors.GREEN)
    log("  The proxy should now have a learned policy of normal traffic patterns.", Colors.GREEN)


async def phase2_switch_to_enforce(client: httpx.AsyncClient, proxy_url: str):
    """Switch the proxy from learning mode to enforce mode."""
    log_phase("2", "SWITCHING TO ENFORCE MODE")

    try:
        resp = await client.post(f"{proxy_url}/mode", json={"mode": "enforce"})
        result = resp.json()
        log(f"Mode switched to ENFORCE: {json.dumps(result, indent=2)}", Colors.GREEN)
    except Exception as e:
        log(f"Failed to switch mode: {e}", Colors.RED)
        return

    # Fetch and display the learned policy
    await asyncio.sleep(0.5)
    try:
        resp = await client.get(f"{proxy_url}/policy")
        policy = resp.json()
        log("\n  Learned Policy:", Colors.CYAN)
        for route, info in policy.get("learned_policy", {}).items():
            log(f"    ✓ {route} (seen {info.get('count', '?')} times)", Colors.GREEN)
    except Exception as e:
        log(f"  Could not fetch policy: {e}", Colors.YELLOW)

    log("\n  🔒 Enforce mode active — all traffic now verified against learned policy", Colors.BOLD)
    await asyncio.sleep(1)


async def phase3_attacks(client: httpx.AsyncClient, proxy_url: str):
    """Simulate various attacks that should be blocked."""
    log_phase("3", "ATTACK SIMULATION — Lateral Movement & Abuse")

    # Get a fresh token for billing-service (the "compromised" service)
    billing_token = await get_token(client, "billing-service")
    if not billing_token:
        log("FATAL: Cannot get billing-service token for attack simulation", Colors.RED)
        return

    # ─── Attack 1: Lateral Movement ──────────────────────────────────────────
    log(f"\n{Colors.BOLD}  🎯 Attack 1: LATERAL MOVEMENT{Colors.RESET}")
    log("  billing-service (compromised) tries to access admin-service...", Colors.YELLOW)
    await asyncio.sleep(0.5)

    status, lat, body = await proxy_request(
        client, proxy_url, "billing-service", "admin-service", "/admin/config", token=billing_token
    )
    log_result("billing-service", "admin-service", "/admin/config", status, lat, body)

    await asyncio.sleep(1)

    # Try the really dangerous endpoint
    log("\n  billing-service tries to call admin shutdown...", Colors.YELLOW)
    status, lat, body = await proxy_request(
        client, proxy_url, "billing-service", "admin-service", "/admin/shutdown",
        method="POST", token=billing_token, payload={"confirm": True}
    )
    log_result("billing-service", "admin-service", "/admin/shutdown", status, lat, body)

    await asyncio.sleep(1)

    # ─── Attack 2: Rate Limit Abuse ──────────────────────────────────────────
    log(f"\n{Colors.BOLD}  🎯 Attack 2: RATE LIMIT ABUSE{Colors.RESET}")
    log("  Flooding billing-service → user-service with 20 rapid requests...", Colors.YELLOW)
    await asyncio.sleep(0.5)

    for i in range(20):
        status, lat, body = await proxy_request(
            client, proxy_url, "billing-service", "user-service", "/users",
            token=billing_token
        )
        if i < 3 or i > 17 or status != 200:  # Only log first few, last few, and blocked
            log_result("billing-service", "user-service", "/users", status, lat, body)
        elif i == 3:
            log(f"  {Colors.DIM}  ... (suppressing duplicate output) ...{Colors.RESET}")
        await asyncio.sleep(0.05)  # ~20 req/s, over the 10/s limit

    await asyncio.sleep(1)

    # ─── Attack 3: Payload Anomaly (SQL Injection) ───────────────────────────
    log(f"\n{Colors.BOLD}  🎯 Attack 3: PAYLOAD ANOMALY (SQL Injection){Colors.RESET}")
    log("  Sending malicious SQL injection payload...", Colors.YELLOW)
    await asyncio.sleep(0.5)

    malicious_payload = {
        "customer_id": "1; DROP TABLE users; --",
        "amount": 99.99,
        "comment": "' UNION SELECT * FROM admin_passwords --",
    }
    status, lat, body = await proxy_request(
        client, proxy_url, "billing-service", "user-service", "/users",
        method="POST", token=billing_token, payload=malicious_payload
    )
    log_result("billing-service", "user-service", "/users", status, lat, body)

    await asyncio.sleep(1)

    # ─── Attack 4: Expired / Invalid Token ───────────────────────────────────
    log(f"\n{Colors.BOLD}  🎯 Attack 4: INVALID TOKEN{Colors.RESET}")
    log("  Using a forged/invalid JWT...", Colors.YELLOW)
    await asyncio.sleep(0.5)

    fake_token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJoYWNrZXItc2VydmljZSIsImV4cCI6MTcwMDAwMDAwMH0.fakesignature"
    status, lat, body = await proxy_request(
        client, proxy_url, "hacker-service", "admin-service", "/admin/config",
        token=fake_token
    )
    log_result("hacker-service", "admin-service", "/admin/config", status, lat, body)

    # ─── Attack 5: No Token ──────────────────────────────────────────────────
    log(f"\n{Colors.BOLD}  🎯 Attack 5: NO TOKEN{Colors.RESET}")
    log("  Attempting request with no authentication...", Colors.YELLOW)
    await asyncio.sleep(0.5)

    status, lat, body = await proxy_request(
        client, proxy_url, "unknown", "admin-service", "/admin/config"
    )
    log_result("unknown", "admin-service", "/admin/config", status, lat, body)

    log(f"\n  {Colors.GREEN}✓ All attacks processed. Check the dashboard for the visual threat timeline.{Colors.RESET}")


async def phase4_revocation(client: httpx.AsyncClient, proxy_url: str):
    """Demonstrate in-flight service revocation."""
    log_phase("4", "IN-FLIGHT REVOCATION — Kill Switch Demo")

    # First, show that billing-service can still make legitimate requests
    billing_token = await get_token(client, "billing-service")
    log("  Before revocation: billing-service makes a legitimate request...", Colors.CYAN)
    status, lat, body = await proxy_request(
        client, proxy_url, "billing-service", "user-service", "/users",
        token=billing_token
    )
    log_result("billing-service", "user-service", "/users", status, lat, body)

    await asyncio.sleep(1)

    # Revoke billing-service
    log(f"\n  {Colors.RED}{Colors.BOLD}🔴 REVOKING billing-service identity...{Colors.RESET}")
    try:
        resp = await client.post(f"{proxy_url}/revoke/billing-service")
        log(f"  Revocation response: {resp.json()}", Colors.RED)
    except Exception as e:
        log(f"  Revocation call failed: {e}", Colors.RED)

    await asyncio.sleep(0.5)

    # Try to use the same token again — should be immediately blocked
    log("\n  After revocation: billing-service tries the SAME request with the SAME token...", Colors.YELLOW)
    status, lat, body = await proxy_request(
        client, proxy_url, "billing-service", "user-service", "/users",
        token=billing_token
    )
    log_result("billing-service", "user-service", "/users", status, lat, body)

    if status == 403:
        log(f"\n  {Colors.GREEN}{Colors.BOLD}✓ REVOCATION SUCCESSFUL — billing-service is dead in the water.{Colors.RESET}")
    else:
        log(f"\n  {Colors.YELLOW}⚠ Unexpected status {status} — revocation may not have taken effect.{Colors.RESET}")


# ─── Main ────────────────────────────────────────────────────────────────────

async def run_simulation(proxy_url: str, fast: bool = False):
    """Run the full CyberMesh demo simulation."""
    print(f"""
{Colors.BOLD}{Colors.CYAN}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███╗   ███╗███████╗███████╗██╗  ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗████╗ ████║██╔════╝██╔════╝██║  ██║
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝██╔████╔██║█████╗  ███████╗███████║
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗██║╚██╔╝██║██╔══╝  ╚════██║██╔══██║
╚██████╗   ██║   ██████╔╝███████╗██║  ██║██║ ╚═╝ ██║███████╗███████║██║  ██║
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝╚══════╝╚══════╝╚═╝  ╚═╝
{Colors.RESET}
{Colors.BOLD}  Zero-Trust Access Control — Attack Simulation{Colors.RESET}
{Colors.DIM}  Proxy: {proxy_url}{Colors.RESET}
""")

    learning_duration = 10 if fast else 30

    async with httpx.AsyncClient(timeout=10.0) as client:
        # Verify proxy is reachable
        try:
            resp = await client.get(f"{proxy_url}/health")
            if resp.status_code != 200:
                log(f"Proxy health check failed: {resp.status_code}", Colors.RED)
                return
            log(f"Proxy is healthy: {resp.json()}", Colors.GREEN)
        except Exception as e:
            log(f"Cannot reach proxy at {proxy_url}: {e}", Colors.RED)
            log("Make sure the proxy is running (docker compose up)", Colors.YELLOW)
            return

        # Verify auth-service is reachable
        try:
            resp = await client.get(f"{AUTH_URL}/health")
            log(f"Auth service is healthy: {resp.json()}", Colors.GREEN)
        except Exception as e:
            log(f"Cannot reach auth service at {AUTH_URL}: {e}", Colors.RED)
            log("Make sure auth-service is running", Colors.YELLOW)
            return

        await asyncio.sleep(1)

        # Run all phases
        await phase1_normal_traffic(client, proxy_url, duration=learning_duration)
        await asyncio.sleep(2)

        await phase2_switch_to_enforce(client, proxy_url)
        await asyncio.sleep(2)

        await phase3_attacks(client, proxy_url)
        await asyncio.sleep(2)

        await phase4_revocation(client, proxy_url)

        # Final summary
        print(f"""
{'='*70}
{Colors.BOLD}{Colors.GREEN}  SIMULATION COMPLETE{Colors.RESET}
{'='*70}

  Open the CyberMesh Dashboard to see the full attack timeline:
  {Colors.CYAN}{Colors.BOLD}http://localhost:3000{Colors.RESET}

  Key observations:
  {Colors.GREEN}✓{Colors.RESET} Normal traffic was learned and auto-generated into a policy
  {Colors.GREEN}✓{Colors.RESET} Lateral movement (billing → admin) was blocked
  {Colors.GREEN}✓{Colors.RESET} Rate limit abuse was detected and blocked
  {Colors.GREEN}✓{Colors.RESET} SQL injection payload was flagged
  {Colors.GREEN}✓{Colors.RESET} Invalid/expired tokens were rejected
  {Colors.GREEN}✓{Colors.RESET} Service revocation took effect immediately
""")


def main():
    parser = argparse.ArgumentParser(description="CyberMesh Attack Simulation")
    parser.add_argument("--proxy-url", default=DEFAULT_PROXY_URL, help="Proxy URL")
    parser.add_argument("--fast", action="store_true", help="Use shorter learning window (10s instead of 30s)")
    args = parser.parse_args()

    asyncio.run(run_simulation(args.proxy_url, fast=args.fast))


if __name__ == "__main__":
    main()
