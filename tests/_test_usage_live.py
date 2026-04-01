"""Quick live test: fire commands + scans, check usage updates."""
import httpx
import json

BASE = "http://localhost:8420"

# 1. Login as super-admin
print("=== Admin Login ===")
r = httpx.post(f"{BASE}/api/auth/login", json={
    "email": "admin@shieldpilot.dev",
    "password": "TestAdminPass123!"
})
print(f"Login: {r.status_code}")
if r.status_code != 200:
    print(f"  Body: {r.text[:200]}")
    exit(1)
admin_token = r.json().get("token", "")
admin_headers = {"Authorization": f"Bearer {admin_token}"}

# Admin usage
print("\n=== Admin Usage ===")
r = httpx.get(f"{BASE}/api/usage", headers=admin_headers)
usage = r.json()
print(f"Tier: {usage.get('tier')}, Admin: {usage.get('is_admin')}")
print(f"Commands: {usage.get('commands_used')}/{usage.get('commands_limit')}")
print(f"Scans: {usage.get('scans_used')}/{usage.get('scans_limit')}")

# 2. Register a free test user
print("\n=== Register free user ===")
r = httpx.post(f"{BASE}/api/auth/register", json={
    "email": "testfree99@example.com",
    "password": "TestPass123!",
    "display_name": "Free Tester",
    "tos_accepted": True
})
print(f"Register: {r.status_code} - {r.text[:150]}")

# Login as free user
print("\n=== Free User Login ===")
r = httpx.post(f"{BASE}/api/auth/login", json={
    "email": "testfree99@example.com",
    "password": "TestPass123!"
})
print(f"Login: {r.status_code}")
if r.status_code != 200:
    print(f"  Body: {r.text[:200]}")
    # Try verifying email via admin or skip
    print("  (May need email verification - trying anyway)")

if r.status_code == 200:
    free_token = r.json().get("token", "")
    free_headers = {"Authorization": f"Bearer {free_token}"}

    # Initial usage
    print("\n=== Free User Initial Usage ===")
    r = httpx.get(f"{BASE}/api/usage", headers=free_headers)
    usage_before = r.json()
    print(f"Tier: {usage_before.get('tier')}")
    print(f"Commands: {usage_before.get('commands_used')}/{usage_before.get('commands_limit')}")
    print(f"Scans: {usage_before.get('scans_used')}/{usage_before.get('scans_limit')}")

    # 3. Fire 3 evaluate commands
    print("\n=== Sending 3 evaluate commands ===")
    for i in range(3):
        r = httpx.post(f"{BASE}/api/evaluate", json={
            "command": f"ls -la /tmp/test{i}",
            "working_directory": "/tmp"
        }, headers=free_headers)
        if r.status_code == 200:
            data = r.json()
            print(f"  Cmd {i+1}: risk={data.get('risk_score', '?')}, action={data.get('action', '?')}")
        else:
            print(f"  Cmd {i+1}: {r.status_code} - {r.text[:100]}")

    # 4. Fire 2 scans
    print("\n=== Sending 2 prompt scans ===")
    for i in range(2):
        r = httpx.post(f"{BASE}/api/scan/prompt", json={
            "content": f"Please review this document section {i} for quality.",
            "source": "test"
        }, headers=free_headers)
        if r.status_code == 200:
            data = r.json()
            print(f"  Scan {i+1}: threats={data.get('threats_found', '?')}, clean={data.get('is_clean', '?')}")
        else:
            print(f"  Scan {i+1}: {r.status_code} - {r.text[:100]}")

    # 5. Check updated usage
    print("\n=== Free User Updated Usage ===")
    r = httpx.get(f"{BASE}/api/usage", headers=free_headers)
    usage_after = r.json()
    print(f"Commands: {usage_after.get('commands_used')}/{usage_after.get('commands_limit')} (was {usage_before.get('commands_used')})")
    print(f"Scans: {usage_after.get('scans_used')}/{usage_after.get('scans_limit')} (was {usage_before.get('scans_used')})")
    print(f"Limit reached: {usage_after.get('limit_reached')}")

    cmd_delta = (usage_after.get('commands_used', 0) or 0) - (usage_before.get('commands_used', 0) or 0)
    scan_delta = (usage_after.get('scans_used', 0) or 0) - (usage_before.get('scans_used', 0) or 0)
    print(f"\nCommand delta: +{cmd_delta} (expected +3)")
    print(f"Scan delta: +{scan_delta} (expected +2)")

    if cmd_delta == 3 and scan_delta == 2:
        print("\nUSAGE TRACKING WORKS CORRECTLY!")
    else:
        print(f"\nWARNING: Expected +3 commands and +2 scans")

print("\n=== Done ===")
