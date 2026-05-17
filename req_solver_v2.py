import os
import json
import time
import requests

CLOUD_V2_API_KEY = "" # Dynamically injected by server.py from Admin Panel

def get_v2_balance(api_key):
    try:
        res = requests.get(f"https://api.nopecha.com/status?key={api_key}", timeout=10)
        data = res.json()
        if "credit" in data:
            return float(data["credit"])
    except: pass
    return 0.0

def solve_cloud_v2(sitekey, url, rqdata, proxy=None, useragent=None):
    """
    Solves hCaptcha using the Cloud V2 Token API.
    Does not require a proxy, as it solves it on their cloud, but you can pass one.
    """
    print(f"[*] Starting Cloud V2 API solve for {sitekey} on {url}")
    
    if not url.startswith('http'):
        url = 'https://' + url

    payload = {
        "key": CLOUD_V2_API_KEY,
        "type": "hcaptcha",
        "sitekey": sitekey,
        "url": url,
        "data": {
        }
    }
    
    if rqdata:
        payload["data"]["rqdata"] = rqdata
        print(f"[*] Attaching RQDATA to V2 Payload ({len(rqdata)} bytes)")
        
    if proxy:
        # Standardize proxy format to what Nopecha accepts
        clean = proxy
        for prefix in ('socks5://', 'socks4://', 'http://', 'https://'):
            if clean.lower().startswith(prefix):
                clean = clean[len(prefix):]
                break
        
        if '@' in clean:
            # Format: user:pass@host:port
            auth, hostport = clean.rsplit('@', 1)
            formatted_proxy = f"http://{auth}@{hostport}"
        else:
            parts = clean.split(':')
            if len(parts) == 4:
                # Format: host:port:user:pass
                formatted_proxy = f"http://{parts[2]}:{parts[3]}@{parts[0]}:{parts[1]}"
            else:
                formatted_proxy = f"http://{clean}"
                
        payload["data"]["proxy"] = formatted_proxy
        print(f"[*] Attaching Proxy to V2 Payload: {formatted_proxy}")

    if useragent:
        payload["data"]["useragent"] = useragent
        print(f"[*] Attaching User-Agent to V2 Payload: {useragent[:40]}...")
    
    # Let's send the job request
    print("[*] Submitting job to cloud V2 API...")
    try:
        res = requests.post("https://api.nopecha.com/token", json=payload, timeout=20)
        res_data = res.json()
        print("[*] Submission Response:", res_data)
        
        if "error" in res_data and res_data["error"] != 0:
            print(f"[-] Cloud V2 API Error: {res_data['message']}")
            if res_data["error"] == 11:
                return 'RATE_LIMIT'
            return None
            
        data = res_data.get("data")
        
        # If they returned the token immediately
        if isinstance(data, str) and data.startswith("P1_"):
            print("[+] Solved instantly (Cached)! Token:", data[:50] + "...")
            return data
            
        # If it's a polling job
        job_id = data
        if not job_id:
            print("[-] No job ID returned from Cloud V2.")
            return None
            
        print(f"[*] Job ID: {job_id} | Polling for result...")
        
        start_time = time.time()
        while time.time() - start_time < 120:
            time.sleep(2)
            poll_res = requests.get(f"https://api.nopecha.com/token?key={CLOUD_V2_API_KEY}&id={job_id}")
            try:
                poll_data = poll_res.json()
            except Exception:
                continue
                
            if "error" in poll_data and poll_data["error"] != 0:
                if poll_data["error"] == 14: # Incomplete
                    continue
                print(f"[-] Polling Error: {poll_data}")
                if poll_data["error"] == 11:
                    return 'RATE_LIMIT'
                return None
                
            if "data" in poll_data and poll_data["data"]:
                token = poll_data["data"]
                print(f"[+] Success! Got token in {time.time() - start_time:.1f}s")
                print(f"[+] Token: {token[:60]}...")
                return token
                
        print("[-] Timed out waiting for Cloud V2")
        return None
        
    except Exception as e:
        print(f"[-] Exception during Cloud V2 request: {e}")
        return None

if __name__ == "__main__":
    test_sitekey = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
    test_url = "https://discord.com/register"
    test_rqdata = "Fw/JtA+U387VY6aPF7obxrL8yvKOWxu3KEUAIbRG4l+o98ypDBhBAtkbL1F5L+q0V8AKi0T8/4Z2BzcnpVlg+AsnDVcxKo+B9BnKsuhQJxNqJQop1ecdL2mivZVttgesKg36eiMCmPQxSOpXiJit/E4o/QiZBR2hlcIpdnPotwnANkU6Sl0yfjvQZa7eclM5kjmRbiFvXbxkhcruE53fQ8x7"
    solve_cloud_v2(test_sitekey, test_url, test_rqdata)
