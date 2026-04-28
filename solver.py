import tls_client, re, json, asyncio, inspect
import hashlib

from time import time
from groq import Groq
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor

from logger import logger
from hsw_solver import hsw
from motion import motion_data

session = tls_client.Session(client_identifier="chrome_120", random_tls_extension_order=True)

api_js = session.get('https://hcaptcha.com/1/api.js?render=explicit&onload=hcaptchaOnLoad').text
version = re.findall(r'v1\/([A-Za-z0-9]+)\/static', api_js)[1]
import os
from dotenv import load_dotenv
load_dotenv('config.env')

client = Groq(api_key=os.environ.get("GROQ_API_KEY"))

session.headers = {
    'accept': '*/*',
    'accept-language': 'en-US,en;q=0.9',
    'cache-control': 'no-cache',
    'pragma': 'no-cache',
    'referer': 'https://discord.com/',
    'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120", "Google Chrome";v="120"',
    'sec-ch-ua-mobile': '?0',
    'sec-ch-ua-platform': '"Windows"',
    'sec-fetch-dest': 'script',
    'sec-fetch-mode': 'no-cors',
    'sec-fetch-site': 'cross-site',
    'user-agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
}

class hcaptcha:
    def __init__(self, sitekey: str, host: str, proxy: str = None, rqdata: str = None) -> None:
        logger.info(f"Solving for: {sitekey} - {host}")
        self.sitekey = sitekey
        self.host = host.split("//")[-1].split("/")[0]

        self.rqdata = rqdata
        self.motion = motion_data(session.headers["user-agent"], f"https://{host}")

        self.motiondata = self.motion.get_captcha()
        self.siteconfig = self.get_siteconfig()

        self.captcha1 = self.get_captcha1()
        self.captcha2 = self.get_captcha2()

        self.answers = {}


    def get_siteconfig(self) -> dict:
        s = time()
        siteconfig = session.post(f"https://api2.hcaptcha.com/checksiteconfig", params={
            'v': version,
            'sitekey': self.sitekey,
            'host': self.host,
            'sc': '1', 
            'swa': '1', 
            'spst': '1'
        })
        return siteconfig.json()


    def get_captcha1(self) -> dict:
        s = time()
        data = {
            'v': version,
            'sitekey': self.sitekey,
            'host': self.host,
            'hl': 'de',
            'motionData': json.dumps(self.motiondata),
            'pdc':  {"s": round(datetime.now().timestamp() * 1000), "n":0, "p":0, "gcs":10},
            'n': asyncio.run(hsw(self.siteconfig['c']['req'], self.host, self.sitekey)),
            'c': json.dumps(self.siteconfig['c']),
            'pst': False
        }

        if self.rqdata is not None: data['rqdata'] = self.rqdata

        getcaptcha = session.post(f"https://api.hcaptcha.com/getcaptcha/{self.sitekey}", data=data)
        return getcaptcha.json()
    
    def get_captcha2(self) -> dict:
        s = time()
        data = {
            'v': version,
            'sitekey': self.sitekey,
            'host': self.host,
            'hl': 'de',
            'a11y_tfe': 'true',
            'action': 'challenge-refresh',
            'old_ekey'  : self.captcha1['key'],
            'extraData': self.captcha1,
            'motionData': json.dumps(self.motiondata),
            'pdc':  {"s": round(datetime.now().timestamp() * 1000), "n":0, "p":0, "gcs":10},
            'n': asyncio.run(hsw(self.captcha1['c']['req'], self.host, self.sitekey)),
            'c': json.dumps(self.captcha1['c']),
            'pst': False
        }
        if self.rqdata is not None: data['rqdata'] = self.rqdata

        getcaptcha2 = session.post(f"https://api.hcaptcha.com/getcaptcha/{self.sitekey}", data=data)
        return getcaptcha2.json()

    def text(self, task: dict) -> str:
        s, q = time(), task.get("datapoint_text", {}).get("de", str(task))
        req_q = self.captcha2.get("requester_question", {}).get("de", "")
        
        # Combine instructions if they differ, otherwise just use q
        full_question = q if not req_q or req_q in q else f"{req_q} {q}"
        
        hashed_q = hashlib.sha1(q.encode()).hexdigest() 
        logger.info(f"questin:\n{full_question}")
        
        # HCaptcha frequently asks string manipulation questions that LLMs struggle with
        # e.g "Lösche alle Vorkommen von 4 in 423408."
        import re
        if "vorkommen" in full_question.lower():
            digits = re.findall(r'\d+', full_question)
            if len(digits) == 2 and len(digits[0]) == 1:
                native_ans = digits[1].replace(digits[0], "")
                logger.info(f"Answer (Native Regex):\n{native_ans}")
                self.answers[hashed_q] = native_ans
                return task['task_key'], {'text': native_ans}
                
        try:
            response = client.chat.completions.create(
                messages=[
                    {"role": "user", 
                     "content": f"You are an expert AI solving text captchas. Solve this short German logic/math puzzle. Read the question carefully, and respond with ONLY the exact final answer (no extra text, no explanations, just the correct word or number).\nQuestion: {full_question}"}
                     ],
                     model="llama-3.3-70b-versatile",
                     temperature=0.1,
                     max_tokens=64,
            )
        
            
            if response:
                response_text = response.choices[0].message.content.strip().replace(".", "")
                logger.info(f"Answer:\n{response_text}")
                self.answers[hashed_q] = response_text
                return task['task_key'], {'text': response_text}
        except Exception as e:
            logger.error(f"Groq exception: {e}")
            
        logger.warning("Groq response empty/failed, defaulting to ja")
        return task['task_key'], {'text': "ja"}

    def solve(self) -> str:
        s = time()
        try:
            cap = self.captcha2
            with ThreadPoolExecutor() as e: 
                results = list(e.map(self.text, cap['tasklist']))
            answers = {key: value for key, value in results}
            submit = session.post(
                f"https://api.hcaptcha.com/checkcaptcha/{self.sitekey}/{cap['key']}",
                json={
                    'answers': answers,
                    'c': json.dumps(cap['c']),
                    'job_mode': cap['request_type'],
                    'motionData': json.dumps(self.motion.check_captcha()),
                    'n': asyncio.run(hsw(cap['c']['req'], self.host, self.sitekey)),
                    'serverdomain': self.host,
                    'sitekey': self.sitekey,
                    'v': version,
                })
            if 'UUID' in submit.text:
                logger.info(f"Solved hCaptcha {submit.json()['generated_pass_UUID'][:150]}..")
                return submit.json()['generated_pass_UUID']
            
            logger.critical(f"Failed To Solve hCaptcha")
            return None
        except Exception as e:
            line = inspect.currentframe().f_back.f_lineno
            logger.critical(f"Error at line {line}: {e}")

if __name__ == "__main__":
    rqdata = "Fw/JtA+U387VY6aPF7obxrL8yvKOWxu3KEUAIbRG4l+o98ypDBhBAtkbL1F5L+q0V8AKi0T8/4Z2BzcnpVlg+AsnDVcxKo+B9BnKsuhQJxNqJQop1ecdL2mivZVttgesKg36eiMCmPQxSOpXiJit/E4o/QiZBR2hlcIpdnPotwnANkU6Sl0yfjvQZa7eclM5kjmRbiFvXbxkhcruE53fQ8x7"
    solver = hcaptcha("a9b5fb07-92ff-493f-86fe-352a2803b3df", "discord.com", None, rqdata)
    token = solver.solve()
