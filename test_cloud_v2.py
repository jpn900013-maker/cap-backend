import time
import sys

# Import the cloud v2 solver
try:
    import req_solver_v2
except ImportError:
    print("[-] Error: req_solver_v2.py not found in this directory.")
    sys.exit(1)

# Put your NoPECHA API key here (e.g. sub_xxxxx...)
TEST_API_KEY = "sub_1TRsxQCRwBwvt6ptak6lPEDg"

def run_test():
    print("=" * 50)
    print("  Testing 9Captcha Cloud V2 (NoPECHA proxy)")
    print("=" * 50)
    
    # Inject the key into the module just like the generator does
    req_solver_v2.CLOUD_V2_API_KEY = TEST_API_KEY
    
    # Target details
    target_sitekey = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
    target_url = "https://discord.com/register"
    target_rqdata = "test_rqdata_goes_here"
    
    print("\n[*] Initializing solve request...")
    print(f"[*] Target: {target_url} ({target_sitekey})")
    print(f"[*] Using Key: {req_solver_v2.CLOUD_V2_API_KEY[:15]}...")
    print()
    
    # Check balance first
    bal = req_solver_v2.get_v2_balance(req_solver_v2.CLOUD_V2_API_KEY)
    print(f"[*] Current Cloud V2 Balance: ${bal:.2f}")
    if bal <= 0:
        print("[-] Warning: Balance is 0 or key is invalid.")
    
    # Automatically test the provided nullproxies endpoint
    test_proxy = "5c70cfb85350c7c5901d:cffa6b1a761020aa@gw.dataimpulse.com:10000"

    start_time = time.time()
    
    # Run the solver
    token = req_solver_v2.solve_cloud_v2(
        sitekey=target_sitekey,
        url=target_url,
        rqdata=target_rqdata,
        proxy=test_proxy
    )
    
    elapsed = time.time() - start_time
    
    if token == 'RATE_LIMIT':
        print("\n[-] The API Key hit a Rate Limit (HTTP 429 / Error 11)!")
        print("[-] Make sure you have multiple keys configured in Admin Panel.")
    elif token:
        print("\n[+] SUCCESS!")
        print(f"[+] Token generated in {elapsed:.1f}s")
        print(f"[+] Token Value: {token[:60]}...")
    else:
        print("\n[-] FAILED to get token. Check output above for errors.")

if __name__ == "__main__":
    run_test()
