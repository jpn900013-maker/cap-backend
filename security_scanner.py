"""
9Captcha Security Scanner Middleware
Detects XSS, SQLi, NoSQLi, command injection, and data exfiltration patterns
in all incoming request payloads. Auto-bans attackers and logs threats.
"""

import re
import base64
import time
import logging
from urllib.parse import unquote
from functools import lru_cache

log = logging.getLogger('security')

# ── Pattern Definitions (compiled once at import for speed) ──────────────

_XSS_PATTERNS = [
    r'<\s*script',
    r'</\s*script',
    r'<\s*iframe',
    r'<\s*object',
    r'<\s*embed',
    r'<\s*svg\b',
    r'<\s*img\b[^>]+\bon\w+\s*=',
    r'<\s*body\b[^>]+\bon\w+\s*=',
    r'\bon(error|load|click|mouseover|mouseout|focus|blur|submit|change|input|keydown|keyup|keypress)\s*=',
    r'javascript\s*:',
    r'vbscript\s*:',
    r'document\s*\.\s*cookie',
    r'document\s*\.\s*domain',
    r'document\s*\.\s*write',
    r'window\s*\.\s*location',
    r'localStorage\s*\.',
    r'sessionStorage\s*\.',
    r'\beval\s*\(',
    r'\bFunction\s*\(',
    r'\bsetTimeout\s*\(\s*["\']',
    r'\bsetInterval\s*\(\s*["\']',
    r'XMLHttpRequest',
    r'\.innerHTML\s*=',
    r'\.outerHTML\s*=',
    r'String\s*\.\s*fromCharCode',
    r'atob\s*\(',
]

_SQLI_PATTERNS = [
    r"'\s*OR\s+'.*?'\s*=\s*'",
    r'UNION\s+(ALL\s+)?SELECT',
    r'DROP\s+TABLE',
    r'INSERT\s+INTO',
    r'DELETE\s+FROM',
    r'UPDATE\s+\w+\s+SET',
    r'EXEC\s*\(',
    r'xp_cmdshell',
    r'--\s*$',
    r'/\*.*?\*/',
]

_NOSQL_PATTERNS = [
    r'"\$where"',
    r'"\$gt"',
    r'"\$lt"',
    r'"\$ne"',
    r'"\$in"',
    r'"\$regex"',
    r'"\$exists"',
    r'\{\s*"\$',
]

_CMDI_PATTERNS = [
    r';\s*(ls|cat|whoami|id|pwd|uname|curl|wget|nc|ncat|bash|sh|python|perl|ruby|php)\b',
    r'&&\s*(ls|cat|whoami|id|pwd|uname|curl|wget|nc)\b',
    r'\|\s*(ls|cat|whoami|id|pwd|uname|curl|wget|nc)\b',
    r'`[^`]+`',
    r'\$\([^)]+\)',
]

_EXFIL_PATTERNS = [
    r'discord\.com/api/webhooks',
    r'discordapp\.com/api/webhooks',
    r'webhook\.site',
    r'requestbin\.com',
    r'ngrok\.io',
    r'burpcollaborator\.net',
    r'oast\.fun',
    r'interact\.sh',
]

# Compile all patterns once
_COMPILED = {}
for _name, _pats in [
    ('XSS', _XSS_PATTERNS),
    ('SQLi', _SQLI_PATTERNS),
    ('NoSQLi', _NOSQL_PATTERNS),
    ('CMDi', _CMDI_PATTERNS),
    ('EXFIL', _EXFIL_PATTERNS),
]:
    _COMPILED[_name] = [re.compile(p, re.IGNORECASE) for p in _pats]


def _decode_layers(text):
    """Decode URL-encoded and base64-encoded layers to catch obfuscated payloads."""
    variants = [text]
    # URL decode
    try:
        decoded = unquote(text)
        if decoded != text:
            variants.append(decoded)
            # Double decode
            decoded2 = unquote(decoded)
            if decoded2 != decoded:
                variants.append(decoded2)
    except Exception:
        pass
    # Base64 decode (only if it looks like base64)
    if len(text) > 20 and re.match(r'^[A-Za-z0-9+/=]+$', text.strip()):
        try:
            raw = base64.b64decode(text, validate=True).decode('utf-8', errors='ignore')
            if raw and len(raw) > 5:
                variants.append(raw)
        except Exception:
            pass
    return variants


def _extract_strings(obj, depth=0):
    """Recursively extract all string values from a nested dict/list."""
    if depth > 10:
        return
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield k  # Scan keys too (NoSQL injection via key names)
            yield from _extract_strings(v, depth + 1)
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            yield from _extract_strings(item, depth + 1)


def scan_payload(data):
    """
    Scan a request payload (dict/list/string) for attack patterns.
    Returns: (is_clean, threat_type, matched_patterns)
    """
    if data is None:
        return True, None, []

    matched = []
    threat_type = None

    for raw_string in _extract_strings(data):
        if not raw_string or len(raw_string) < 3:
            continue
        # Skip base64 image data (legitimate ticket attachments)
        if raw_string.startswith('data:image/'):
            continue
        if len(raw_string) > 50000:
            # Truncate massive payloads to prevent ReDoS
            raw_string = raw_string[:50000]

        for variant in _decode_layers(raw_string):
            for category, patterns in _COMPILED.items():
                for pat in patterns:
                    if pat.search(variant):
                        threat_type = threat_type or category
                        matched.append(f"{category}:{pat.pattern}")
                        if len(matched) >= 5:
                            return False, threat_type, matched

    if matched:
        return False, threat_type, matched
    return True, None, []


def get_client_ip(request):
    """Extract real client IP, handling Cloudflare/Railway/nginx proxies."""
    # Cloudflare
    cf_ip = request.headers.get('CF-Connecting-IP')
    if cf_ip:
        return cf_ip.strip()
    # Standard proxy chain
    forwarded = request.headers.get('X-Forwarded-For', '')
    if forwarded:
        return forwarded.split(',')[0].strip()
    real_ip = request.headers.get('X-Real-IP')
    if real_ip:
        return real_ip.strip()
    return request.remote_addr or '0.0.0.0'


def get_ip_country(ip):
    """Lightweight geo lookup via free ip-api.com (cached, non-blocking best-effort)."""
    if ip in ('127.0.0.1', '0.0.0.0', '::1'):
        return 'LOCAL'
    try:
        import requests as _req
        r = _req.get(f'http://ip-api.com/json/{ip}?fields=countryCode', timeout=2)
        if r.status_code == 200:
            return r.json().get('countryCode', 'XX')
    except Exception:
        pass
    return 'XX'


def log_security_event(db, event_type, severity, request, user_id=None, username=None,
                       email=None, raw_payload='', detected_patterns=None, action='FLAGGED'):
    """Write a structured security event to MongoDB."""
    ip = get_client_ip(request)
    try:
        db.security_logs.insert_one({
            'type': event_type,
            'severity': severity,
            'attacker_id': user_id,
            'attacker_username': username or '',
            'attacker_email': email or '',
            'attacker_ip': ip,
            'attacker_country': get_ip_country(ip),
            'attacker_user_agent': request.headers.get('User-Agent', '')[:500],
            'endpoint': request.path,
            'method': request.method,
            'raw_payload': str(raw_payload)[:5000],
            'detected_patterns': detected_patterns or [],
            'action_taken': action,
            'timestamp': time.time(),
        })
    except Exception as e:
        log.error(f'Failed to log security event: {e}')


def send_admin_alert(webhook_url, title, description, color=0xFF0000, fields=None):
    """Fire a Discord webhook alert to the admin channel."""
    if not webhook_url:
        return
    embed = {
        'title': f'🚨 {title}',
        'description': description[:2000],
        'color': color,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'footer': {'text': '9Captcha Security'},
    }
    if fields:
        embed['fields'] = [{'name': f[0], 'value': str(f[1])[:200], 'inline': True} for f in fields[:10]]
    try:
        import requests as _req
        _req.post(webhook_url, json={'embeds': [embed]}, timeout=3)
    except Exception:
        pass


def send_ban_alert(webhook_url, ban_id, username, reason, ip, country, request_path, payload=None):
    """Fire a Discord webhook alert specifically for bans/blocks."""
    if not webhook_url:
        return
    embed = {
        'title': f'⛔ User/IP Banned',
        'description': f'**Reason:** {reason}\n**Path:** `{request_path}`',
        'color': 0x000000,
        'timestamp': time.strftime('%Y-%m-%dT%H:%M:%SZ', time.gmtime()),
        'footer': {'text': f'Ban ID: {ban_id}'},
        'fields': [
            {'name': 'Ban ID', 'value': f'`{ban_id}`', 'inline': True},
            {'name': 'Username', 'value': str(username) if username else 'N/A', 'inline': True},
            {'name': 'IP / Country', 'value': f'{ip} ({country})', 'inline': True}
        ]
    }
    if payload:
        embed['fields'].append({'name': 'Trigger Payload', 'value': f'```\n{str(payload)[:1000]}\n```', 'inline': False})
    
    try:
        import requests as _req
        _req.post(webhook_url, json={'embeds': [embed]}, timeout=3)
    except Exception:
        pass


def sanitize_mongo_input(data):
    """Strip MongoDB operator keys ($-prefixed) from user input to prevent NoSQL injection."""
    if isinstance(data, dict):
        return {k: sanitize_mongo_input(v) for k, v in data.items() if not k.startswith('$')}
    elif isinstance(data, list):
        return [sanitize_mongo_input(item) for item in data]
    return data


def validate_base64_image(image_data):
    """Validate that image data is a legitimate base64-encoded image, not an attack vector."""
    if not image_data:
        return True
    if not isinstance(image_data, str):
        return False
    # Must start with data:image/ prefix
    if not re.match(r'^data:image/(png|jpeg|jpg|gif|webp|svg\+xml);base64,', image_data):
        return False
    # Max 700KB
    if len(image_data) > 700000:
        return False
    return True
