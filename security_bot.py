import os
import time
import uuid
import logging
from dotenv import load_dotenv
from pymongo import MongoClient
import requests

# Load env variables strictly from config.env
load_dotenv('config.env')

from security_scanner import scan_payload, send_ban_alert
from encryption import decrypt_field

logging.basicConfig(level=logging.INFO, format='%(asctime)s - SECURITY_BOT - %(message)s')
log = logging.getLogger('security_bot')

MONGO_URI = os.environ.get('MONGO_URI')
TICKETS_MONGO_URI = os.environ.get('TICKETS_MONGO_URI')
DB_NAME = os.environ.get('DB_NAME', '9captcha_db')
TICKETS_DB_NAME = os.environ.get('TICKETS_DB_NAME', 'ticket_system')
BAN_WEBHOOK_URL = os.environ.get('BAN_WEBHOOK_URL', '')

POLL_INTERVAL = 15  # seconds

def get_clients():
    main_client = MongoClient(MONGO_URI, tlsAllowInvalidCertificates=True)
    ticket_client = MongoClient(TICKETS_MONGO_URI, tlsAllowInvalidCertificates=True)
    return main_client[DB_NAME], ticket_client[TICKETS_DB_NAME]

def scan_tickets(tdb, db):
    """Scan all tickets. If malicious, delete ticket and ban the user."""
    tickets = list(tdb.tickets.find({}))
    for t in tickets:
        is_clean, threat, patterns = scan_payload(t)
        if not is_clean:
            log.warning(f"Malicious Ticket Detected! Threat: {threat}, Patterns: {patterns}")
            user_id = t.get('user_id')
            username = t.get('username')
            
            # Delete ticket immediately
            tdb.tickets.delete_one({'_id': t['_id']})
            log.info(f"Deleted malicious ticket {t['_id']}")
            
            # Ban the user if we know their ID
            if user_id:
                ban_id = str(uuid.uuid4())[:8]
                db.users.update_one(
                    {'_id': user_id}, 
                    {'$set': {'is_banned': True, 'ban_reason': f'System Bot Detect: {threat} in ticket', 'ban_id': ban_id}}
                )
                log.info(f"Banned user {username} for malicious ticket payload.")
                try:
                    user_record = db.users.find_one({'_id': user_id})
                    raw_ip = decrypt_field(user_record.get('registration_ip', '')) if user_record else 'Unknown'
                    country = user_record.get('registration_country', 'XX') if user_record else 'XX'
                    send_ban_alert(BAN_WEBHOOK_URL, ban_id, username, f"Malicious Ticket ({threat})", raw_ip, country, "/tickets", str(patterns))
                except Exception as e:
                    log.error(f"Error alerting webhook: {e}")

def scan_users(db):
    """Scan users for malicious usernames/emails."""
    # Only scan active users to avoid infinite repeating on already banned/cleaned
    users = list(db.users.find({'is_banned': {'$ne': True}}))
    for u in users:
        payload_container = {
            'username': u.get('username', ''),
        }
        # Only decrypt email for scanning if it exists
        if u.get('email'):
            payload_container['email'] = decrypt_field(u['email'])
            
        is_clean, threat, patterns = scan_payload(payload_container)
        if not is_clean:
            log.warning(f"Malicious Profile Detected! Threat: {threat}, User: {u.get('username')}")
            
            ban_id = str(uuid.uuid4())[:8]
            # Ban user
            db.users.update_one(
                {'_id': u['_id']},
                {'$set': {'is_banned': True, 'ban_reason': f'System Bot Detect: {threat} in profile', 'ban_id': ban_id}}
            )
            
            raw_ip = decrypt_field(u.get('registration_ip', ''))
            country = u.get('registration_country', 'XX')
            
            # Blacklist the IP so they can't reconnect
            if raw_ip:
                db.blacklisted_ips.update_one(
                    {'ip': raw_ip},
                    {'$set': {'ip': raw_ip, 'active': True, 'reason': f'Bot Ban: {threat}', 'ban_id': ban_id}},
                    upsert=True
                )
            
            log.info(f"Banned user {u.get('username')} and blacklisted IP {raw_ip}.")
            
            try:
                send_ban_alert(BAN_WEBHOOK_URL, ban_id, u.get('username'), f"Malicious Profile Data ({threat})", raw_ip, country, "/profile", str(patterns))
            except Exception as e:
                pass


def main():
    log.info("Starting 9Captcha Continuous Security Bot...")
    try:
        db, tdb = get_clients()
    except Exception as e:
        log.error(f"Failed to connect to MongoDB: {e}")
        return

    while True:
        try:
            scan_tickets(tdb, db)
            scan_users(db)
        except Exception as e:
            log.error(f"Error during scan cycle: {e}")
            
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
