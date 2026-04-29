import tls_client, re, json, inspect, random
import hashlib

from time import time
from groq import Groq
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from logger import logger
from hsw_solver import hsw
from motion import motion_data

# Chrome-only desktop UAs that match chrome_120 TLS fingerprint.
# Tuples: (user_agent_string, chrome_major_version, platform_for_sec_ch_ua)
CHROME_USER_AGENTS = [
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120", "Windows"),
    ("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120", "Windows"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.225 Safari/537.36", "120", "Windows"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120", "macOS"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_2_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120", "macOS"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120", "Linux"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", "121", "Windows"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", "121", "macOS"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", "121", "Linux"),
    ("Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", "121", "Windows"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36", "119", "Windows"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36", "119", "macOS"),
    ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "122", "Windows"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "122", "macOS"),
    ("Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36", "122", "Linux"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36", "120", "macOS"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6_4) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", "121", "macOS"),
    ("Mozilla/5.0 (Macintosh; Intel Mac OS X 14_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36", "121", "macOS"),
]


def _detect_platform(ua: str) -> str:
    """Detect OS platform from a User-Agent string for sec-ch-ua-platform."""
    if 'Macintosh' in ua or 'Mac OS X' in ua:
        return 'macOS'
    elif 'Linux' in ua:
        return 'Linux'
    return 'Windows'


# Fetch hCaptcha version at startup (shared, read-only)
_init_session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)
_init_session.headers = {
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
}
api_js = _init_session.get('https://hcaptcha.com/1/api.js?render=explicit&onload=hcaptchaOnLoad').text
version = re.findall(r'v1\/([A-Za-z0-9]+)\/static', api_js)[1]

import os
from dotenv import load_dotenv
load_dotenv('config.env')

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))


def _build_headers(ua: str, chrome_ver: str, platform: str) -> dict:
    """Build a fully consistent Chrome header set.
    
    Matches: TLS fingerprint (chrome_120) ↔ sec-ch-ua ↔ sec-ch-ua-platform ↔ User-Agent ↔ accept-language
    """
    return {
        'sec-ch-ua-platform': f'"{platform}"',
        'user-agent': ua,
        'accept': 'application/json',
        'sec-ch-ua': f'"Not_A Brand";v="8", "Chromium";v="{chrome_ver}", "Google Chrome";v="{chrome_ver}"',
        'sec-ch-ua-mobile': '?0',
        'origin': 'https://newassets.hcaptcha.com',
        'sec-fetch-site': 'same-site',
        'sec-fetch-mode': 'cors',
        'sec-fetch-dest': 'empty',
        'referer': 'https://newassets.hcaptcha.com/',
        'accept-encoding': 'gzip, deflate, br',
        'accept-language': 'en-US,en;q=0.9',
    }


class hcaptcha:
    def __init__(self, sitekey: str, host: str, proxy: str = None, rqdata: str = None, useragent: str = None) -> None:
        self.solve_start = time()
        logger.info(f"Solving for: {sitekey} - {host}")
        self.sitekey = sitekey
        self.host = host.split("//")[-1].split("/")[0]
        self.rqdata = rqdata

        # Pick UA: client-provided or random Chrome UA
        if useragent:
            ua = useragent
            m = re.search(r'Chrome/(\d+)', ua)
            chrome_ver = m.group(1) if m else "120"
            platform = _detect_platform(ua)
        else:
            ua, chrome_ver, platform = random.choice(CHROME_USER_AGENTS)

        self.ua = ua
        self.chrome_ver = chrome_ver
        self.platform = platform
        self.headers = _build_headers(ua, chrome_ver, platform)

        # Per-solve session — thread safe, no shared state
        self.session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)
        self.session.headers = self.headers
        
        if proxy:
            parts = proxy.split(":")
            if len(parts) == 4:
                ip, port, user, pwd = parts
                formatted_proxy = f"http://{user}:{pwd}@{ip}:{port}"
            else:
                formatted_proxy = f"http://{proxy}" if not proxy.startswith("http") else proxy
            self.session.proxies = {"http": formatted_proxy, "https": formatted_proxy}

        # Motion data with matching UA (uses en-US language internally)
        self.motion = motion_data(ua, f"https://{self.host}")
        self.motiondata = self.motion.get_captcha()

        # Chain: siteconfig → captcha1 → captcha2
        self.siteconfig = self.get_siteconfig()
        self.captcha1 = self.get_captcha1()
        self.captcha2 = self.get_captcha2()

        self.answers = {}

    def get_siteconfig(self) -> dict:
        s = time()
        siteconfig = self.session.post("https://api2.hcaptcha.com/checksiteconfig", params={
            'v': version,
            'sitekey': self.sitekey,
            'host': self.host,
            'sc': '1',
            'swa': '1',
            'spst': '1',
        })
        logger.info(f"checksiteconfig", start_time=s, end_time=time())
        return siteconfig.json()

    def get_captcha1(self) -> dict:
        s = time()
        data = {
            'v': version,
            'sitekey': self.sitekey,
            'host': self.host,
            'hl': 'en',
            'motionData': json.dumps(self.motiondata),
            'pdc': {"s": round(datetime.now().timestamp() * 1000), "n": 0, "p": 0, "gcs": 10},
            'n': hsw(self.siteconfig['c']['req'], self.host, self.sitekey),
            'c': json.dumps(self.siteconfig['c']),
            'pst': False,
        }
        if self.rqdata is not None:
            data['rqdata'] = self.rqdata

        getcaptcha = self.session.post(f"https://api.hcaptcha.com/getcaptcha/{self.sitekey}", data=data)
        logger.info(f"getcaptcha1", start_time=s, end_time=time())
        return getcaptcha.json()

    def get_captcha2(self) -> dict:
        s = time()
        data = {
            'v': version,
            'sitekey': self.sitekey,
            'host': self.host,
            'hl': 'en',
            'a11y_tfe': 'true',
            'action': 'challenge-refresh',
            'old_ekey': self.captcha1['key'],
            'extraData': self.captcha1,
            'motionData': json.dumps(self.motiondata),
            'pdc': {"s": round(datetime.now().timestamp() * 1000), "n": 0, "p": 0, "gcs": 10},
            'n': hsw(self.captcha1['c']['req'], self.host, self.sitekey),
            'c': json.dumps(self.captcha1['c']),
            'pst': False,
        }
        if self.rqdata is not None:
            data['rqdata'] = self.rqdata

        getcaptcha2 = self.session.post(f"https://api.hcaptcha.com/getcaptcha/{self.sitekey}", data=data)
        logger.info(f"getcaptcha2", start_time=s, end_time=time())
        return getcaptcha2.json()

    def text(self, task: dict) -> tuple:
        """Solve a single text captcha task. Returns (task_key, answer_dict)."""
        s = time()
        q = task.get("datapoint_text", {}).get("en", str(task))
        req_q = self.captcha2.get("requester_question", {}).get("en", "")
        full_question = q if not req_q or req_q in q else f"{req_q} {q}"
        hashed_q = hashlib.sha1(q.encode()).hexdigest()
        logger.info(f"question:\n{full_question}")

        lower_q = full_question.lower()
        ans = None

        # ---- Native solvers (instant, no LLM needed) ----

        # 1. DELETE pattern: "Delete/Remove/Lösche all occurrences of X in Y"
        if any(kw in lower_q for kw in ['delete', 'remove', 'lösche', 'vorkommen', 'entferne']):
            digits = re.findall(r'\d+', full_question)
            if len(digits) >= 2:
                # Find the single digit to delete and the number
                single_digits = [d for d in digits if len(d) == 1]
                numbers = [d for d in digits if len(d) >= 4]
                if single_digits and numbers:
                    ans = numbers[-1].replace(single_digits[0], "")

        # 2. REPLACE LAST CHARACTER pattern (universal — handles ALL observed variants)
        # Variants seen:
        #   "Replace the last character with 3 only when the ending character is 6 in 985283"
        #   "When the final character is 8, change only that last character to 2 in 506877"
        #   "Only if the ending is 0, replace the last character with 8 in 631416"
        #   "If it ends with 3, replace that final 3 with 9 in 993493"
        #   "Ersetze das letzte Zeichen durch X wenn das Endzeichen Y ist in Z"
        elif any(kw in lower_q for kw in ['last character', 'last digit', 'letzte', 'final character', 'final digit', 'ending character', 'ending is', 'ends with', 'endzeichen']):
            digits = re.findall(r'\d+', full_question)
            numbers = [d for d in digits if len(d) >= 4]
            single_digits = [d for d in digits if len(d) == 1]
            
            if numbers and len(single_digits) >= 2:
                number = numbers[-1]  # The big number to modify
                
                # Figure out which single digit is "replace with" and which is "condition"
                # Strategy: find the condition digit (what the last char must be) and replacement digit
                # Look for keywords near each digit to determine roles
                
                # Find positions of single digits in the text
                replace_digit = None
                condition_digit = None
                
                for sd in single_digits:
                    # Find position of this digit in the question
                    pos = full_question.find(sd)
                    # Get surrounding context (30 chars before)
                    context_before = full_question[max(0, pos-40):pos].lower()
                    context_after = full_question[pos:pos+40].lower()
                    
                    if any(kw in context_before for kw in ['with', 'to', 'durch', 'zu']):
                        replace_digit = sd
                    elif any(kw in context_before for kw in ['is', 'ends', 'ending', 'final', 'endzeichen', 'wenn']):
                        condition_digit = sd
                    elif any(kw in context_after for kw in ['replace', 'change', 'ersetze', 'ändere']):
                        condition_digit = sd
                
                # If we couldn't determine roles from context, use order heuristic:
                # In most patterns, the first single digit mentioned after "with/to" is replace,
                # and the one near "is/ends" is condition 
                if replace_digit is None or condition_digit is None:
                    # Fallback: try all pairs and pick the consistent one
                    for i, sd1 in enumerate(single_digits):
                        for j, sd2 in enumerate(single_digits):
                            if i != j:
                                # Try sd1=replace, sd2=condition
                                if replace_digit is None:
                                    replace_digit = sd1
                                if condition_digit is None:
                                    condition_digit = sd2
                                break
                        if replace_digit and condition_digit:
                            break
                
                if replace_digit and condition_digit and number:
                    if number[-1] == condition_digit:
                        ans = number[:-1] + replace_digit
                    else:
                        ans = number
                    logger.info(f"[REGEX-LAST] condition={condition_digit} replace={replace_digit} number={number} → {ans}")

        # 3. REPLACE FIRST CHARACTER pattern
        elif any(kw in lower_q for kw in ['first character', 'first digit', 'erste']):
            digits = re.findall(r'\d+', full_question)
            numbers = [d for d in digits if len(d) >= 4]
            single_digits = [d for d in digits if len(d) == 1]
            if numbers and single_digits:
                number = numbers[-1]
                new_char = single_digits[0]
                ans = new_char + number[1:]

        # 4. Simple arithmetic
        elif not ans:
            arith_match = re.search(r'(\d+)\s*([+\-*/×÷])\s*(\d+)', full_question)
            if arith_match:
                a, op, b = int(arith_match.group(1)), arith_match.group(2), int(arith_match.group(3))
                if op in ('+',): ans = str(a + b)
                elif op in ('-',): ans = str(a - b)
                elif op in ('*', '×'): ans = str(a * b)
                elif op in ('/', '÷'): ans = str(a // b) if b != 0 else "0"
                else: ans = str(a + b)

        # Return native answer if found
        if ans is not None:
            logger.info(f"Answer (native):\n{ans}")
            self.answers[hashed_q] = ans
            return task['task_key'], {'text': ans}

        # ---- LLM fallback ----
        try:
            response = client.chat.completions.create(
                messages=[{
                    "role": "user",
                    "content": (
                        "You are solving a text captcha. Read VERY carefully.\n"
                        "RULES:\n"
                        "- If asked to replace the last character: check if the condition is met FIRST. "
                        "If the last digit does NOT match the condition, return the number UNCHANGED.\n"
                        "- If asked to delete occurrences of a digit: remove ALL instances of that digit.\n"
                        "- Respond with ONLY the final number, nothing else.\n\n"
                        f"Question: {full_question}"
                    )
                }],
                model="llama-3.3-70b-versatile",
                temperature=0.0,
                max_tokens=32,
            )

            if response:
                response_text = response.choices[0].message.content.strip()
                response_text = re.sub(r'[^0-9]', '', response_text)  # Keep only digits
                if response_text:
                    logger.info(f"Answer (LLM):\n{response_text}")
                    self.answers[hashed_q] = response_text
                    return task['task_key'], {'text': response_text}
        except Exception as e:
            logger.error(f"Groq exception: {e}")

        logger.warning("All solvers failed, defaulting to 0")
        return task['task_key'], {'text': "0"}

    def solve(self) -> str:
        s = time()
        try:
            cap = self.captcha2
            
            if not cap.get('tasklist'):
                logger.critical(f"No tasklist in captcha2 response: {json.dumps(cap)[:200]}")
                return None

            with ThreadPoolExecutor() as e:
                results = list(e.map(self.text, cap['tasklist']))

            answers = {key: value for key, value in results}
            
            hsw_start = time()
            n_token = hsw(cap['c']['req'], self.host, self.sitekey)
            logger.info(f"checkcaptcha HSW", start_time=hsw_start, end_time=time())

            submit = self.session.post(
                f"https://api.hcaptcha.com/checkcaptcha/{self.sitekey}/{cap['key']}",
                json={
                    'answers': answers,
                    'c': json.dumps(cap['c']),
                    'job_mode': cap['request_type'],
                    'motionData': json.dumps(self.motion.check_captcha()),
                    'n': n_token,
                    'serverdomain': self.host,
                    'sitekey': self.sitekey,
                    'v': version,
                })

            elapsed = round(time() - self.solve_start, 1)
            
            if 'UUID' in submit.text:
                token = submit.json()['generated_pass_UUID']
                logger.info(f"Solved hCaptcha in {elapsed}s — {token[:60]}...")
                return token

            logger.critical(f"Failed in {elapsed}s: {submit.text[:200]}")
            return None
        except Exception as e:
            line = inspect.currentframe().f_back.f_lineno if inspect.currentframe().f_back else 0
            logger.critical(f"Error at line {line}: {e}")
            return None


if __name__ == "__main__":
    rqdata = "Fw/JtA+U387VY6aPF7obxrL8yvKOWxu3KEUAIbRG4l+o98ypDBhBAtkbL1F5L+q0V8AKi0T8/4Z2BzcnpVlg+AsnDVcxKo+B9BnKsuhQJxNqJQop1ecdL2mivZVttgesKg36eiMCmPQxSOpXiJit/E4o/QiZBR2hlcIpdnPotwnANkU6Sl0yfjvQZa7eclM5kjmRbiFvXbxkhcruE53fQ8x7"
    solver = hcaptcha("a9b5fb07-92ff-493f-86fe-352a2803b3df", "discord.com", None, rqdata)
    token = solver.solve()
