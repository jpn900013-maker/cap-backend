import os
from groq import Groq
from dotenv import load_dotenv

load_dotenv("C:/programs/project/project/DC/new/cap/nocap/RazorCap-main/RazorCap-main/9captcha-req/backend/config.env")

env_keys = os.environ.get("GROQ_API_KEY", "")
pool = []
for k in env_keys.split(","):
    k = k.strip()
    if k and k not in pool:
        pool.append(k)

print(f"Testing {len(pool)} keys...")

for i, key in enumerate(pool):
    print(f"\n--- Key {i+1} ---")
    try:
        client = Groq(api_key=key, max_retries=0)
        res = client.chat.completions.create(
            messages=[{"role": "user", "content": "hello"}],
            model="llama-3.3-70b-versatile",
            max_tokens=5,
            temperature=0
        )
        print("Status: WORKING (Token fetched successfully)")
        print("Response:", res.choices[0].message.content.strip())
    except Exception as e:
        print(f"Status: FAILED")
        print(f"Reason: {e}")
