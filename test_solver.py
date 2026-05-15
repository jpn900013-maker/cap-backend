"""
9Captcha VPS Diagnostic — Remote API Test
==========================================
Calls the live VPS backend API to create a request-solver task,
polls for the result, and checks the logs endpoint to see what happened.
"""

import requests
import time
import json
import sys

# ── Configuration ──
VPS_URL   = "https://9captcha-api.pridesmp.fun"
API_KEY   = "9cap-579c091d-e9cc-4d11-a882-17a6a2f394b7"
LOGS_KEY  = "0po98iu76yt5@SSS"
SITEKEY   = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
SITEURL   = "discord.com"

print("=" * 60)
print("  9Captcha — Remote VPS Solver Diagnostic")
print("=" * 60)
print(f"  Backend: {VPS_URL}")
print()

# ── Step 1: Check if VPS is alive ──
print("[1/4] Pinging VPS backend...")
try:
    r = requests.get(f"{VPS_URL}/captcha/api/", timeout=10)
    print(f"  ✓ VPS responded — HTTP {r.status_code} ({len(r.text)} bytes)")
except Exception as e:
    print(f"  ✗ VPS unreachable: {e}")
    sys.exit(1)

# ── Step 2: Clear old logs so we only see fresh ones ──
print("\n[2/4] Clearing old logs on VPS...")
try:
    r = requests.post(f"{VPS_URL}/captcha/api/logs/clear?key={LOGS_KEY}", timeout=5)
    print(f"  ✓ Logs cleared — {r.json()}")
except Exception as e:
    print(f"  ⚠ Could not clear logs: {e}")

# ── Step 3: Create a request-solver task ──
print("\n[3/4] Creating request-solver task on VPS...")
payload = {
    "key": API_KEY,
    "type": "hcaptcha_basic",
    "data": {
        "sitekey": SITEKEY,
        "siteurl": SITEURL,
        "proxy": "http://6y2uquze0:kLSIlf3E4F@global.nullproxies.com:8080",
        "rqdata": "",
        "useragent": ""
    }
}

try:
    s = time.time()
    r = requests.post(f"{VPS_URL}/captcha/api/create_task", json=payload, timeout=30)
    elapsed = round(time.time() - s, 2)
    print(f"  Response ({elapsed}s): HTTP {r.status_code}")
    print(f"  Body: {r.text[:500]}")
    
    if r.status_code != 200:
        print(f"\n  ✗ Task creation FAILED with HTTP {r.status_code}")
        print("  → Fetching logs to see why...")
        # Jump to logs
    else:
        data = r.json()
        task_id = data.get("task_id")
        print(f"  ✓ Task created: {task_id}")
        
        # ── Poll for result ──
        print(f"\n  Polling for result (max 120s)...")
        poll_start = time.time()
        last_status = None
        
        while time.time() - poll_start < 120:
            time.sleep(3)
            try:
                r2 = requests.get(
                    f"{VPS_URL}/captcha/api/get_result/{task_id}?key={API_KEY}",
                    timeout=10
                )
                d = r2.json()
                status = d.get("status")
                
                if status != last_status:
                    elapsed = round(time.time() - poll_start, 1)
                    print(f"  [{elapsed}s] Status: {status}")
                    last_status = status
                
                if status == "solved":
                    token = d.get("solution", "")
                    print(f"\n  ✓✓✓ SOLVED!")
                    print(f"  Token: {token[:80]}...")
                    break
                elif status == "error":
                    print(f"\n  ✗ SOLVER ERROR: {d.get('error', 'unknown')}")
                    break
                    
            except Exception as e:
                print(f"  Poll error: {e}")
        else:
            print(f"\n  ✗ TIMEOUT — task stayed in '{last_status}' for 120s")
            print("  The solver thread likely crashed silently.")

except Exception as e:
    print(f"  ✗ Request failed: {e}")

# ── Step 4: Fetch fresh logs ──
print("\n[4/4] Fetching VPS server logs...")
print("-" * 60)
try:
    r = requests.get(f"{VPS_URL}/captcha/api/logs/data?key={LOGS_KEY}", timeout=10)
    data = r.json()
    logs = data.get("logs", [])
    
    if not logs:
        print("  ⚠ NO LOGS CAPTURED!")
        print("  This confirms the solver thread crashed before logging anything,")
        print("  OR Gunicorn workers are forked and MemoryLogHandler is isolated.")
        print()
        print("  FIX: Restart the VPS server using:")
        print("    gunicorn --bind 0.0.0.0:5000 --workers 1 --threads 4 --timeout 120 --preload server:app")
    else:
        print(f"  [{len(logs)} log lines captured]")
        print()
        for line in logs:
            print(f"  {line}")
    
    stats = data.get("stats", {})
    if stats:
        print()
        print(f"  ── VPS System Stats ──")
        print(f"  CPU: {stats.get('cpu_percent', '?')}%")
        print(f"  RAM: {stats.get('ram_used_mb', '?')} / {stats.get('ram_total_mb', '?')} MB ({stats.get('ram_percent', '?')}%)")
        print(f"  Uptime: {stats.get('uptime', '?')}")

except Exception as e:
    print(f"  ✗ Could not fetch logs: {e}")

print()
print("=" * 60)
print("  Diagnostic complete")
print("=" * 60)
