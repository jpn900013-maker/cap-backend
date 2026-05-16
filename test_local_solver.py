import sys, os
from dotenv import load_dotenv
load_dotenv('config.env') # load groq key!

# Import the original native solver
from solver import hcaptcha

sitekey = "a9b5fb07-92ff-493f-86fe-352a2803b3df"
url = "discord.com"
ua = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
rqdata = "Fw/JtA+U387VY6aPF7obxrL8yvKOWxu3KEUAIbRG4l+o98ypDBhBAtkbL1F5L+q0V8AKi0T8/4Z2BzcnpVlg+AsnDVcxKo+B9BnKsuhQJxNqJQop1ecdL2mivZVttgesKg36eiMCmPQxSOpXiJit/E4o/QiZBR2hlcIpdnPotwnANkU6Sl0yfjvQZa7eclM5kjmRbiFvXbxkhcruE53fQ8x7"

test_proxy = None 

print(f"[*] Testing ORIGINAL Native solver with proxy: {test_proxy}")
solver = hcaptcha(sitekey, url, test_proxy, rqdata, useragent=ua)
token = solver.solve()
print(f"[+] Token: {token}")
