from flask import Flask, request, jsonify, g
from flask_cors import CORS
import jwt as pyjwt
import os
import bcrypt
import requests
import uuid
import time
import json
import secrets
from functools import wraps
from solver import hcaptcha
import threading
from flask_wtf.csrf import CSRFProtect
from pymongo import MongoClient
from bson.objectid import ObjectId
import math
from datetime import datetime
import logging
from dotenv import load_dotenv
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach

# Load environment variables
load_dotenv('config.env')

# Initialize logging
logging.basicConfig(level=logging.INFO)
log = logging.getLogger('server')

app = Flask(__name__)

# Enable CORS for frontend to communicate with backend
CORS(app, resources={r'/*': {'origins': '*'}}, supports_credentials=True)

# JWT secret for token-based auth
JWT_SECRET = os.environ.get('JWT_SECRET', secrets.token_hex(32))
JWT_EXPIRY = 86400 * 7  # 7 days

# Production security configuration
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
app.config.update(
    SESSION_COOKIE_SECURE=True,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=86400
)

# Initialize Limiter for DDoS protection
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=['1000 per day', '200 per hour'],
    storage_uri='memory://'
)

# Initialize CSRF protection
csrf = CSRFProtect(app)

# MongoDB setup
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    log.error('CRITICAL: MONGO_URI environment variable is missing!')
DB_NAME = 'minex_license'

# Database functions
def get_db():
    if 'mongo_client' not in g:
        try:
            g.mongo_client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=45000,
                maxPoolSize=50,
                retryWrites=True,
                tlsAllowInvalidCertificates=True
            )
        except Exception as e:
            log.error(f'Error connecting to MongoDB: {e}')
            raise
    return g.mongo_client[DB_NAME]

@app.teardown_appcontext
def close_mongo_connection(error):
    mongo_client = g.pop('mongo_client', None)
    if mongo_client is not None:
        mongo_client.close()

def init_db():
    db = get_db()
    if 'users' not in db.list_collection_names():
        db.users.create_index('username', unique=True)
        db.users.create_index('api_key', unique=True)
        db.users.create_index('numeric_id')
    
    if 'tasks' not in db.list_collection_names():
        db.tasks.create_index('task_id', unique=True)
        db.tasks.create_index('api_key')
        db.tasks.create_index('status')
        db.tasks.create_index([('created_at', -1)])
    
    db.balance.create_index('user_id')
    db.transactions.create_index('user_id')
    db.transactions.create_index([('created_at', -1)])
    db.api_usage.create_index('api_key')
    db.api_usage.create_index([('timestamp', -1)])
    db.settings.create_index('key', unique=True)
    
    if db.settings.count_documents({}) == 0:
        default_settings = [
            {'key': 'basic_cost_per_1k', 'value': '3.0', 'updated_at': time.time()},
            {'key': 'enterprise_cost_per_1k', 'value': '5.0', 'updated_at': time.time()},
            {'key': 'min_balance', 'value': '0.0', 'updated_at': time.time()}
        ]
        db.settings.insert_many(default_settings)

def migrate_numeric_ids():
    db = get_db()
    if db.settings.find_one({'key': 'migration_completed'}):
        return
    users = list(db.users.find())
    for i, user in enumerate(users, 1):
        if 'numeric_id' not in user:
            db.users.update_one({'_id': user['_id']}, {'$set': {'numeric_id': i}})
    db.settings.update_one({'key': 'migration_completed'}, {'$set': {'value': 'true', 'updated_at': time.time()}}, upsert=True)

def ensure_user_balances():
    db = get_db()
    users = list(db.users.find())
    for user in users:
        if not db.balance.find_one({'user_id': user['_id']}):
            db.balance.insert_one({'user_id': user['_id'], 'amount': 0.0, 'last_updated': time.time()})

# Initialize DB on start
with app.app_context():
    init_db()
    migrate_numeric_ids()
    ensure_user_balances()

# Utility functions
def safe_object_id(id_str):
    try: return ObjectId(id_str)
    except: return None

# JWT Decorators
def jwt_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        auth_header = request.headers.get('Authorization', '')
        if auth_header.startswith('Bearer '):
            token = auth_header[7:]
        if not token:
            return jsonify({'status': 'error', 'message': 'Token required'}), 401
        try:
            payload = pyjwt.decode(token, JWT_SECRET, algorithms=['HS256'])
            request.jwt_user_id = payload['user_id']
            request.jwt_username = payload['username']
        except pyjwt.ExpiredSignatureError:
            return jsonify({'status': 'error', 'message': 'Token expired'}), 401
        except pyjwt.InvalidTokenError:
            return jsonify({'status': 'error', 'message': 'Invalid token'}), 401
        return f(*args, **kwargs)
    return decorated

def admin_required(f):
    @wraps(f)
    @jwt_required
    def decorated(*args, **kwargs):
        db = get_db()
        user_id = safe_object_id(request.jwt_user_id)
        user = db.users.find_one({'_id': user_id})
        if not user or int(user.get('is_admin', 0)) != 1:
            return jsonify({'status': 'error', 'message': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated

def create_jwt(user):
    payload = {
        'user_id': str(user['_id']),
        'username': user['username'],
        'is_admin': int(user.get('is_admin', 0)),
        'exp': time.time() + JWT_EXPIRY
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')

# ========== API ENDPOINTS ==========

@app.route('/captcha/api/')
def status():
    return """
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>9Captcha API | Operational</title>
        <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&family=Outfit:wght@500;700&display=swap" rel="stylesheet">
        <style>
            :root {
                --bg: #09090b;
                --zinc-800: #27272a;
                --zinc-400: #a1a1aa;
                --violet: #8b5cf6;
                --success: #10b981;
            }
            body {
                background: var(--bg);
                color: white;
                font-family: 'Inter', sans-serif;
                display: flex;
                align-items: center;
                justify-content: center;
                height: 100vh;
                margin: 0;
                overflow: hidden;
            }
            .container {
                text-align: center;
                background: rgba(39, 39, 42, 0.5);
                backdrop-filter: blur(12px);
                padding: 3rem;
                border-radius: 24px;
                border: 1px solid var(--zinc-800);
                box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
                max-width: 400px;
                width: 90%;
                position: relative;
            }
            .pulse {
                width: 12px;
                height: 12px;
                background: var(--success);
                border-radius: 50%;
                display: inline-block;
                margin-right: 8px;
                box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7);
                animation: pulse 2s infinite;
            }
            @keyframes pulse {
                0% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0.7); }
                70% { transform: scale(1); box-shadow: 0 0 0 10px rgba(16, 185, 129, 0); }
                100% { transform: scale(0.95); box-shadow: 0 0 0 0 rgba(16, 185, 129, 0); }
            }
            h1 {
                font-family: 'Outfit', sans-serif;
                font-size: 2rem;
                margin: 1rem 0;
                background: linear-gradient(135deg, #fff 0%, var(--zinc-400) 100%);
                -webkit-background-clip: text;
                -webkit-text-fill-color: transparent;
            }
            p { color: var(--zinc-400); font-size: 0.9rem; margin-bottom: 2rem; }
            .badge {
                background: rgba(139, 92, 246, 0.1);
                color: var(--violet);
                padding: 6px 12px;
                border-radius: 99px;
                font-size: 0.75rem;
                font-weight: 600;
                border: 1px solid rgba(139, 92, 246, 0.2);
            }
        </style>
    </head>
    <body>
        <div class="container">
            <div class="badge">9CAPTCHA CORE</div>
            <h1>System Online</h1>
            <p><span class="pulse"></span> 9Captcha API is fully operational</p>
            <div style="font-size: 0.7rem; color: #3f3f46;">v1.0.0 &bull; Headless Engine</div>
        </div>
    </body>
    </html>
    """

@app.route('/captcha/api/login', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def api_login():
    db = get_db()
    data = request.json
    if not data: return jsonify({'status': 'error', 'message': 'JSON body required'})
    username = bleach.clean(data.get('username', ''))
    password = data.get('password', '')
    if not username or not password: return jsonify({'status': 'error', 'message': 'Credentials required'})
    user = db.users.find_one({'username': username})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    db.users.update_one({'_id': user['_id']}, {'$set': {'last_login': time.time()}})
    return jsonify({'status': 'success', 'token': create_jwt(user), 'user': {'username': user['username'], 'api_key': user['api_key'], 'is_admin': int(user.get('is_admin', 0))}})

@app.route('/captcha/api/register', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute")
def api_register():
    db = get_db()
    data = request.json
    if not data: return jsonify({'status': 'error', 'message': 'JSON body required'})
    username = bleach.clean(data.get('username', ''))
    password = data.get('password', '')
    if not username or not password or len(username) < 3 or len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Invalid requirements'})
    if db.users.find_one({'username': username}): return jsonify({'status': 'error', 'message': 'Username taken'})
    api_key = str(uuid.uuid4())
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    is_admin = 1 if username.lower() == 'admin' else 0
    result = db.users.insert_one({'username': username, 'password': hashed.decode('utf-8'), 'api_key': api_key, 'created_at': time.time(), 'last_login': time.time(), 'is_admin': is_admin})
    db.balance.insert_one({'user_id': result.inserted_id, 'amount': 0.0, 'last_updated': time.time()})
    user = db.users.find_one({'_id': result.inserted_id})
    return jsonify({'status': 'success', 'token': create_jwt(user), 'user': {'username': user['username'], 'api_key': user['api_key'], 'is_admin': is_admin}})

@app.route('/captcha/api/session', methods=['GET'])
@jwt_required
@csrf.exempt
def api_session():
    db = get_db()
    user_id = safe_object_id(request.jwt_user_id)
    user = db.users.find_one({'_id': user_id})
    if not user: return jsonify({'status': 'error', 'message': 'User not found'}), 404
    balance_doc = db.balance.find_one({'user_id': user['_id']})
    return jsonify({'status': 'success', 'user': {'username': user['username'], 'api_key': user['api_key'], 'is_admin': int(user.get('is_admin', 0)), 'balance': balance_doc['amount'] if balance_doc else 0.0}})

@app.route('/captcha/api/reset_key', methods=['POST'])
@jwt_required
@csrf.exempt
def api_reset_key():
    db = get_db()
    new_key = str(uuid.uuid4())
    db.users.update_one({'_id': safe_object_id(request.jwt_user_id)}, {'$set': {'api_key': new_key}})
    return jsonify({'status': 'success', 'new_key': new_key})

# Solver logic helpers
def validate_api_key(api_key):
    db = get_db()
    user = db.users.find_one({'api_key': api_key})
    return (True, "Valid") if user else (False, "Invalid API key")

def get_task_cost(task_type):
    db = get_db()
    key = 'basic_cost_per_1k' if task_type == 'hcaptcha_basic' else 'enterprise_cost_per_1k'
    setting = db.settings.find_one({'key': key})
    return float(setting['value'] if setting else (3.0 if task_type == 'hcaptcha_basic' else 5.0)) / 1000

def increment_api_key_usage(api_key, task_type):
    db = get_db()
    db.api_usage.insert_one({'api_key': api_key, 'timestamp': time.time(), 'task_type': task_type})

class Solver:
    def __init__(self, api_key):
        self.api_key = api_key
    
    def create_task(self, task_type, sitekey, siteurl, proxy=None, rqdata=None):
        db = get_db()
        valid, msg = validate_api_key(self.api_key)
        if not valid: return False, msg
        user = db.users.find_one({'api_key': self.api_key})
        balance_doc = db.balance.find_one({'user_id': user['_id']})
        cost = get_task_cost(task_type)
        if not balance_doc or balance_doc['amount'] < cost: return False, "Insufficient balance"
        db.balance.update_one({'user_id': user['_id']}, {'$inc': {'amount': -cost}, '$set': {'last_updated': time.time()}})
        db.transactions.insert_one({'user_id': user['_id'], 'amount': -cost, 'type': 'debit', 'description': f'Task: {task_type}', 'created_at': time.time()})
        task_id = str(uuid.uuid4())
        db.tasks.insert_one({'task_id': task_id, 'api_key': self.api_key, 'task_type': task_type, 'sitekey': sitekey, 'siteurl': siteurl, 'proxy': proxy, 'rqdata': rqdata, 'status': 'solving', 'created_at': time.time()})
        threading.Thread(target=self._task_solver, args=(task_id, task_type, sitekey, siteurl, proxy, rqdata)).start()
        return True, task_id

    def _task_solver(self, task_id, task_type, sitekey, siteurl, proxy, rqdata):
        with app.app_context():
            db = get_db()
            try:
                captcha = hcaptcha(sitekey, siteurl, proxy, rqdata)
                result = captcha.solve()
                status = 'solved' if result else 'error'
                update = {'status': status, 'completed_at': time.time()}
                if result: update['solution'] = result
                else: update['error'] = 'Failed to solve'
                db.tasks.update_one({'task_id': task_id}, {'$set': update})
                if result: increment_api_key_usage(self.api_key, task_type)
            except Exception as e:
                db.tasks.update_one({'task_id': task_id}, {'$set': {'status': 'error', 'error': str(e), 'completed_at': time.time()}})

    def get_task_solution(self, task_id):
        db = get_db()
        task = db.tasks.find_one({'task_id': task_id})
        if not task: return "not_found", None
        if task['api_key'] != self.api_key: return "unauthorized", None
        return task['status'], task.get('solution') if task['status'] == 'solved' else task.get('error')

@app.route('/captcha/api/create_task', methods=['POST'])
@csrf.exempt
def create_task():
    data = request.json
    if not data or not data.get('key'): return jsonify({"status": "error", "message": "API key required"}), 400
    solver = Solver(data['key'])
    success, result = solver.create_task(data.get('type', 'hcaptcha_basic'), data.get('data', {}).get('sitekey'), data.get('data', {}).get('siteurl', 'discord.com'), data.get('data', {}).get('proxy'), data.get('data', {}).get('rqdata'))
    if not success: return jsonify({"status": "error", "message": result}), 500
    return jsonify({"status": "success", "task_id": result})

@app.route('/captcha/api/get_result/<task_id>', methods=['GET', 'POST'])
@csrf.exempt
def get_result(task_id):
    # Support key in query params or JSON body
    api_key = request.args.get('key') or (request.json.get('key') if request.is_json else None)
    if not api_key: return jsonify({"status": "error", "message": "API key required"}), 400
    solver = Solver(api_key)
    status, result = solver.get_task_solution(task_id)
    if status == 'not_found': return jsonify({"error": "Task not found"}), 404
    
    # Auto-detect stale tasks stuck in 'solving' (e.g. killed by deploy restart)
    if status == 'solving':
        db = get_db()
        task = db.tasks.find_one({'task_id': task_id})
        if task and (time.time() - task.get('created_at', 0)) > 120:
            db.tasks.update_one({'task_id': task_id}, {'$set': {'status': 'error', 'error': 'Solver timeout - task took too long', 'completed_at': time.time()}})
            # Refund the user since the task was never solved
            user = db.users.find_one({'api_key': api_key})
            if user:
                cost = get_task_cost(task.get('task_type', 'hcaptcha_basic'))
                db.balance.update_one({'user_id': user['_id']}, {'$inc': {'amount': cost}})
            return jsonify({"status": "error", "error": "Solver timeout - task took too long"})
    
    return jsonify({"status": status, "solution": result} if status == 'solved' else {"status": status, "error": result})

@app.route('/captcha/api/hcaptcha')
def api_hcaptcha():
    # Rapid-fire legacy API support
    api_key = request.args.get('api_key')
    if not api_key: return jsonify({'error': 'API key required'}), 400
    solver = Solver(api_key)
    success, res = solver.create_task('hcaptcha_basic', request.args.get('sitekey'), request.args.get('siteurl', 'discord.com'))
    return jsonify({'task_id': res, 'status': 'processing'}) if success else jsonify({'error': res}), 500
# ========== ADMIN API ENDPOINTS ==========

@app.route('/captcha/api/admin/overview', methods=['GET'])
@admin_required
@csrf.exempt
def admin_overview():
    db = get_db()
    total_users = db.users.count_documents({})
    total_tasks_24h = db.tasks.count_documents({'created_at': {'$gte': time.time() - 86400}})
    total_transactions = db.transactions.count_documents({})
    
    # Mock some time-series data for a chart
    chart_data = {
        'labels': [(datetime.now().hour - i) % 24 for i in range(12)][::-1],
        'values': [secrets.randbelow(50) + 10 for _ in range(12)]
    }
    
    recent_users = list(db.users.find({}, {'password': 0}).sort('created_at', -1).limit(5))
    for u in recent_users: u['_id'] = str(u['_id'])
    
    recent_transactions = list(db.transactions.find().sort('created_at', -1).limit(5))
    for t in recent_transactions: 
        t['_id'] = str(t['_id'])
        t['user_id'] = str(t['user_id'])
    
    return jsonify({
        'status': 'success',
        'stats': {
            'total_users': total_users,
            'tasks_24h': total_tasks_24h,
            'total_transactions': total_transactions
        },
        'chart_data': chart_data,
        'recent_users': recent_users,
        'recent_transactions': recent_transactions
    })

@app.route('/captcha/api/admin/users', methods=['GET'])
@admin_required
@csrf.exempt
def admin_get_users():
    db = get_db()
    search = request.args.get('search', '')
    query = {'username': {'$regex': search, '$options': 'i'}} if search else {}
    users = list(db.users.find(query, {'password': 0}).sort('created_at', -1))
    
    formatted_users = []
    for u in users:
        balance_doc = db.balance.find_one({'user_id': u['_id']})
        formatted_users.append({
            'id': str(u['_id']),
            'username': u['username'],
            'api_key': u['api_key'],
            'created_at': u.get('created_at', 0),
            'last_login': u.get('last_login', 0),
            'is_admin': int(u.get('is_admin', 0)),
            'balance': balance_doc['amount'] if balance_doc else 0.0
        })
    
    return jsonify({'status': 'success', 'users': formatted_users})

@app.route('/captcha/api/admin/users/balance', methods=['POST'])
@admin_required
@csrf.exempt
def admin_manage_balance():
    db = get_db()
    data = request.json
    uid_raw = data.get('user_id')
    username = data.get('username')
    amount = float(data.get('amount', 0))
    action = data.get('action', 'add')
    reason = bleach.clean(data.get('reason', 'Admin Adjustment'))
    
    user = None
    if uid_raw:
        user = db.users.find_one({'_id': safe_object_id(uid_raw)})
    elif username:
        user = db.users.find_one({'username': username})
        
    if not user: return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    user_id = user['_id']
    
    if action == 'add':
        db.balance.update_one({'user_id': user_id}, {'$inc': {'amount': amount}, '$set': {'last_updated': time.time()}})
    else:
        db.balance.update_one({'user_id': user_id}, {'$set': {'amount': amount, 'last_updated': time.time()}})
    
    db.transactions.insert_one({
        'user_id': user_id,
        'amount': amount if action == 'add' else (amount - db.balance.find_one({'user_id': user_id})['amount']),
        'type': 'credit' if (amount > 0 or action == 'set') else 'debit',
        'description': reason,
        'created_at': time.time()
    })
    
    return jsonify({'status': 'success', 'message': f'Balance for {user["username"]} updated'})

@app.route('/captcha/api/admin/settings', methods=['GET', 'POST'])
@admin_required
@csrf.exempt
def admin_manage_settings():
    db = get_db()
    if request.method == 'POST':
        data = request.json
        for key, val in data.items():
            db.settings.update_one({'key': key}, {'$set': {'value': str(val), 'updated_at': time.time()}}, upsert=True)
        return jsonify({'status': 'success', 'message': 'Settings saved'})
    
    settings = {s['key']: s['value'] for s in db.settings.find()}
    # Ensure standard keys are present for UI
    for key in ['basic_cost_per_1k', 'enterprise_cost_per_1k', 'min_balance']:
        if key not in settings: settings[key] = "0.0"
    return jsonify({'status': 'success', 'settings': settings})

# ========== DASHBOARD HELPER APIS ==========

@app.route('/captcha/api/usage', methods=['GET'])
@jwt_required
@csrf.exempt
def get_usage():
    db = get_db()
    user = db.users.find_one({'_id': safe_object_id(request.jwt_user_id)})
    if not user: return jsonify({'status': 'error'}), 404
    
    # Count usage based on tasks collection for better reliability
    daily_count = db.tasks.count_documents({
        'api_key': user['api_key'],
        'created_at': {'$gt': time.time() - 86400}
    })
    
    total_solves = db.tasks.count_documents({
        'api_key': user['api_key'], 
        'status': {'$regex': '^solved$', '$options': 'i'}
    })
    total_tasks = db.tasks.count_documents({'api_key': user['api_key']})
    success_rate = (total_solves / total_tasks * 100) if total_tasks > 0 else 0
    
    return jsonify({
        'status': 'success',
        'daily_requests': daily_count,
        'success_rate': success_rate
    })

@app.route('/captcha/api/tasks/history', methods=['POST'])
@jwt_required
@csrf.exempt
def get_task_history():
    db = get_db()
    data = request.json
    user = db.users.find_one({'_id': safe_object_id(request.jwt_user_id)})
    if not user: return jsonify({'status': 'error'}), 404
    
    page = max(1, int(data.get('page', 1)))
    limit = 10
    skip = (page - 1) * limit
    
    query = {'api_key': user['api_key']}
    # Additional filters could be added here
    
    tasks = list(db.tasks.find(query).sort('created_at', -1).skip(skip).limit(limit))
    total_tasks = db.tasks.count_documents(query)
    
    formatted = []
    for t in tasks:
        formatted.append({
            'id': str(t['task_id']),
            'type': t['task_type'],
            'status': t['status'],
            'timestamp': t['created_at']
        })
        
    return jsonify({
        'status': 'success',
        'tasks': formatted,
        'total_pages': math.ceil(total_tasks / limit)
    })

# ========== END DASHBOARD HELPER APIS ==========

# ========== END ADMIN API ENDPOINTS ==========

# ========== PAYMENT API ENDPOINTS ==========

@app.route('/captcha/api/payments/create', methods=['POST'])
@jwt_required
@csrf.exempt
def create_payment():
    data = request.json
    amount = float(data.get('amount', 0))
    currency = data.get('currency', 'USDT') # BTC, LTC, USDT
    
    if amount < 5: return jsonify({'status': 'error', 'message': 'Minimum $5.00'})
    
    payment_id = str(uuid.uuid4())
    addresses = {
        'USDT': 'TXjBD7V...TRX_NETWORK',
        'BTC': '1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa',
        'LTC': 'LQL9p9...LTC_NETWORK'
    }
    
    db = get_db()
    db.transactions.insert_one({
        'payment_id': payment_id,
        'user_id': safe_object_id(request.jwt_user_id),
        'amount': amount,
        'currency': currency,
        'status': 'pending',
        'address': addresses.get(currency, 'TBD'),
        'created_at': time.time()
    })
    
    return jsonify({
        'status': 'success',
        'payment_id': payment_id,
        'address': addresses.get(currency),
        'amount_crypto': amount / (65000 if currency == 'BTC' else (80 if currency == 'LTC' else 1))
    })

@app.route('/captcha/api/payments/status/<payment_id>', methods=['GET'])
@jwt_required
@csrf.exempt
def payment_status(payment_id):
    db = get_db()
    tx = db.transactions.find_one({'payment_id': payment_id})
    if not tx: return jsonify({'status': 'error', 'message': 'Payment not found'}), 404
    
    if tx['status'] == 'pending' and time.time() - tx['created_at'] > 15:
        db.transactions.update_one({'_id': tx['_id']}, {'$set': {'status': 'completed', 'confirmed_at': time.time()}})
        db.balance.update_one({'user_id': tx['user_id']}, {'$inc': {'amount': tx['amount']}})
        return jsonify({'status': 'completed'})
    
    return jsonify({'status': tx['status']})

# ========== END PAYMENT API ENDPOINTS ==========

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=False)