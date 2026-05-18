"""
9Captcha Field-Level Encryption Module
AES-256-GCM encryption for sensitive data at rest in MongoDB.
"""

import os
import base64
import hashlib
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Encryption key derived from ENCRYPTION_SECRET env var
# In production, set this to a strong 64-char hex string on Railway/Render
_RAW_SECRET = os.environ.get('ENCRYPTION_SECRET', '')
if not _RAW_SECRET:
    _RAW_SECRET = secrets.token_hex(32)
    print('[SECURITY] WARNING: ENCRYPTION_SECRET not set — using ephemeral key. Set it in env vars for persistence!', flush=True)

# Derive a 256-bit key via SHA-256 (ensures consistent key length regardless of input)
_KEY = hashlib.sha256(_RAW_SECRET.encode()).digest()
_NONCE_SIZE = 12  # 96-bit nonce for AES-GCM


def encrypt_field(plaintext):
    """
    Encrypt a string field using AES-256-GCM.
    Returns a base64-encoded string: nonce + ciphertext + tag.
    Safe to store directly in MongoDB as a string field.
    """
    if not plaintext or not isinstance(plaintext, str):
        return plaintext
    try:
        aesgcm = AESGCM(_KEY)
        nonce = secrets.token_bytes(_NONCE_SIZE)
        ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        # Prepend nonce to ciphertext, base64 encode the whole thing
        encrypted = base64.b64encode(nonce + ciphertext).decode('ascii')
        return f'ENC:{encrypted}'
    except Exception as e:
        print(f'[ENCRYPTION] Encrypt error: {e}', flush=True)
        return plaintext


def decrypt_field(encrypted_value):
    """
    Decrypt an AES-256-GCM encrypted field.
    Accepts base64 string prefixed with 'ENC:'.
    Returns plaintext string, or the original value if not encrypted.
    """
    if not encrypted_value or not isinstance(encrypted_value, str):
        return encrypted_value
    if not encrypted_value.startswith('ENC:'):
        return encrypted_value  # Not encrypted, return as-is (backwards compatible)
    try:
        raw = base64.b64decode(encrypted_value[4:])
        nonce = raw[:_NONCE_SIZE]
        ciphertext = raw[_NONCE_SIZE:]
        aesgcm = AESGCM(_KEY)
        plaintext = aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext.decode('utf-8')
    except Exception as e:
        print(f'[ENCRYPTION] Decrypt error: {e}', flush=True)
        return encrypted_value


def encrypt_dict_fields(doc, fields):
    """
    Encrypt specific fields in a dictionary before storing to MongoDB.
    Modifies and returns the dict in-place.
    """
    for field in fields:
        if field in doc and doc[field] and isinstance(doc[field], str):
            if not doc[field].startswith('ENC:'):
                doc[field] = encrypt_field(doc[field])
    return doc


def decrypt_dict_fields(doc, fields):
    """
    Decrypt specific fields in a dictionary after reading from MongoDB.
    Modifies and returns the dict in-place.
    """
    if not doc:
        return doc
    for field in fields:
        if field in doc and doc[field] and isinstance(doc[field], str):
            doc[field] = decrypt_field(doc[field])
    return doc


# Fields that should be encrypted at rest per collection
ENCRYPTED_USER_FIELDS = ['api_key', 'email']
ENCRYPTED_TICKET_FIELDS = []  # Tickets already sanitized, no PII to encrypt
