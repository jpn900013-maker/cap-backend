"""
9Captcha Legacy Data Sanitizer & Encryption Script
Run this script once to:
1. Scan all existing support tickets for malicious XSS/injection payloads and quarantine them.
2. Retroactively encrypt legacy emails, IPs, and User-Agents using AES-256-GCM.
3. Fix missing fields on older user accounts (is_banned, ip_history).
"""

import os
import time
from dotenv import load_dotenv
from pymongo import MongoClient

# Load env variables strictly from config.env
load_dotenv('config.env')

from security_scanner import scan_payload
from encryption import encrypt_field

MONGO_URI = os.environ.get('MONGO_URI')
TICKETS_MONGO_URI = os.environ.get('TICKETS_MONGO_URI')
DB_NAME = os.environ.get('DB_NAME', '9captcha_db')
TICKETS_DB_NAME = os.environ.get('TICKETS_DB_NAME', 'ticket_system')

print("[*] Connecting to Main DB...")
client = MongoClient(MONGO_URI, tlsAllowInvalidCertificates=True)
db = client[DB_NAME]

print("[*] Connecting to Tickets DB...")
tclient = MongoClient(TICKETS_MONGO_URI, tlsAllowInvalidCertificates=True)
tdb = tclient[TICKETS_DB_NAME]

def clean_legacy_tickets():
    print("\n--- Scanning Legacy Tickets ---")
    tickets = list(tdb.tickets.find({}))
    malicious_count = 0
    clean_count = 0
    
    for t in tickets:
        is_clean, threat, patterns = scan_payload(t)
        if not is_clean:
            print(f"[!] Malicious ticket found: {t['_id']} (Threat: {threat})")
            # Move to quarantine
            t['quarantined_at'] = time.time()
            t['detected_threat'] = threat
            t['detected_patterns'] = patterns
            
            try:
                tdb.quarantined_tickets.insert_one(t)
                tdb.tickets.delete_one({'_id': t['_id']})
                malicious_count += 1
            except Exception as e:
                print(f"Error quarantining ticket {t['_id']}: {e}")
        else:
            clean_count += 1
            
    print(f"-> Scanned {len(tickets)} tickets: {clean_count} clean, {malicious_count} quarantined/deleted.")


def migrate_legacy_users():
    print("\n--- Upgrading Legacy Users (Encryption & Scheme Fixes) ---")
    users = list(db.users.find({}))
    updated_count = 0
    
    for u in users:
        updates = {}
        
        # 1. Fix missing basic fields
        if 'is_banned' not in u:
            updates['is_banned'] = False
            updates['ban_reason'] = ''
        if 'ip_history' not in u:
            updates['ip_history'] = []
            
        # 2. Encrypt Email
        if 'email' in u and u['email'] and not str(u['email']).startswith('ENC:'):
            updates['email'] = encrypt_field(u['email'])
            
        # 3. Encrypt Registration IP & UA
        if 'registration_ip' in u and u['registration_ip'] and not str(u['registration_ip']).startswith('ENC:'):
            updates['registration_ip'] = encrypt_field(u['registration_ip'])
        if 'registration_user_agent' in u and u['registration_user_agent'] and not str(u['registration_user_agent']).startswith('ENC:'):
            updates['registration_user_agent'] = encrypt_field(u['registration_user_agent'])
            
        # 4. Encrypt IPs in login_history
        if 'login_history' in u and isinstance(u['login_history'], list):
            new_history = []
            history_changed = False
            for entry in u['login_history']:
                if 'ip' in entry and entry['ip'] and not str(entry['ip']).startswith('ENC:'):
                    entry['ip'] = encrypt_field(entry['ip'])
                    history_changed = True
                new_history.append(entry)
            if history_changed:
                updates['login_history'] = new_history
                
        # 5. Encrypt standalone ip_history
        if 'ip_history' in u and isinstance(u['ip_history'], list):
            new_ip_hist = []
            ip_changed = False
            for ip in u['ip_history']:
                if ip and not str(ip).startswith('ENC:'):
                    new_ip_hist.append(encrypt_field(ip))
                    ip_changed = True
                else:
                    new_ip_hist.append(ip)
            if ip_changed or ('ip_history' in updates and updates['ip_history'] == []):
                updates['ip_history'] = list(set(new_ip_hist))

        if updates:
            db.users.update_one({'_id': u['_id']}, {'$set': updates})
            updated_count += 1
            
    print(f"-> Checked {len(users)} users: securely migrated & encrypted {updated_count} legacy accounts.")


if __name__ == '__main__':
    try:
        clean_legacy_tickets()
        migrate_legacy_users()
        print("\n[+] Cleanup & Migration Complete.")
    except Exception as e:
        print(f"\n[X] Fatal Error: {e}")
