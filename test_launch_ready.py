"""Pre-launch readiness check for ShieldPilot."""
import httpx

base = "https://shieldpilot.dev"
results = []

def check(name, fn):
    try:
        result = fn()
        results.append(("PASS", name, result))
        print(f"  PASS  {name}: {result}")
    except Exception as e:
        results.append(("FAIL", name, str(e)))
        print(f"  FAIL  {name}: {e}")

print("ShieldPilot Launch Readiness Check")
print("=" * 55)

# 1. Site reachable
check("Site reachable", lambda: (
    r := httpx.get(f"{base}/login", timeout=15),
    f"{r.status_code} | {len(r.text)} bytes"
)[-1])

# 2. Health API
check("Health API", lambda: (
    r := httpx.get(f"{base}/api/health", timeout=10),
    h := r.json(),
    f"status={h['status']} | db={h['components']['database']['status']}"
)[-1])

# 3. Static assets
check("app.js loads", lambda: (
    r := httpx.get(f"{base}/static/js/app.js", timeout=10),
    f"{r.status_code} | {len(r.text)} bytes"
)[-1])

check("CSS loads", lambda: (
    r := httpx.get(f"{base}/static/css/sentinel.css", timeout=10),
    f"{r.status_code} | {len(r.text)} bytes"
)[-1])

# 4. Registration works
import secrets
email = f"launch-test-{secrets.token_hex(4)}@test.dev"
check("Registration", lambda: (
    r := httpx.post(f"{base}/api/auth/register", json={
        "email": email,
        "username": f"test_{secrets.token_hex(3)}",
        "password": "LaunchTest123!",
        "tos_accepted": True,
    }, timeout=10),
    f"{r.status_code}"
)[-1])

# 5. Login works
check("Login", lambda: (
    r := httpx.post(f"{base}/api/auth/login", json={
        "username": email,
        "password": "LaunchTest123!",
    }, timeout=10),
    f"{r.status_code} | token={'yes' if r.json().get('access_token') else 'no'}"
)[-1])

# 6. Evaluate command
r = httpx.post(f"{base}/api/auth/login", json={"username": email, "password": "LaunchTest123!"}, timeout=10)
token = r.json().get("access_token", "")
h = {"Authorization": f"Bearer {token}"}

check("Evaluate safe cmd", lambda: (
    r := httpx.post(f"{base}/api/evaluate", json={"command": "ls -la"}, headers=h, timeout=10),
    d := r.json(),
    f"score={d.get('risk_score', '?')} action={d.get('action', '?')}"
)[-1])

# 7. Scan works
check("Prompt scan", lambda: (
    r := httpx.post(f"{base}/api/scan/prompt", json={"content": "Hello world", "source": "test"}, headers=h, timeout=10),
    d := r.json(),
    f"score={d.get('overall_score', '?')} threats={len(d.get('threats', []))}"
)[-1])

# 8. Pricing API
check("Pricing API", lambda: (
    r := httpx.get(f"{base}/api/billing/pricing", headers=h, timeout=10),
    p := r.json(),
    f"tiers={list(p.get('tiers',{}).keys())} stripe={'yes' if p.get('stripe_publishable_key') else 'no'}"
)[-1])

# 9. Dashboard loads
check("Dashboard HTML", lambda: (
    r := httpx.get(f"{base}/", headers=h, timeout=10),
    f"{r.status_code} | {len(r.text)} bytes"
)[-1])

# 10. Google OAuth endpoint exists
check("Google OAuth endpoint", lambda: (
    r := httpx.get(f"{base}/api/auth/google/login", follow_redirects=False, timeout=10),
    f"{r.status_code}"
)[-1])

# 11. No secrets exposed
check("No secrets in health", lambda: (
    r := httpx.get(f"{base}/api/health", timeout=10),
    t := r.text,
    "SAFE" if "password" not in t.lower() and "secret_key" not in t.lower() and "sk_test" not in t else "EXPOSED"
)[-1])

# 12. API docs available
check("API docs", lambda: (
    r := httpx.get(f"{base}/api/docs", timeout=10),
    f"{r.status_code}"
)[-1])

print("=" * 55)
passed = sum(1 for s, _, _ in results if s == "PASS")
failed = sum(1 for s, _, _ in results if s == "FAIL")
print(f"\nResults: {passed} PASS, {failed} FAIL")
if failed == 0:
    print("\nLAUNCH READY.")
else:
    print("\nFIX FAILURES BEFORE LAUNCH.")
