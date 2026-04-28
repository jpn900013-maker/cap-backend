from flask import Flask, request, jsonify, render_template, redirect, url_for, session, flash, g
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

# Initialize logging
log = logging.getLogger('werkzeug')
log.setLevel(logging.ERROR)

from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import bleach

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

# Add Jinja2 filters
@app.template_filter('timestamp_to_date')
def timestamp_to_date(timestamp):
    """Convert a timestamp to a formatted date string."""
    if not timestamp:
        return ""
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))
from dotenv import load_dotenv

# Load `.env` into environment variables
load_dotenv()

# MongoDB setup
MONGO_URI = os.environ.get('MONGO_URI')
if not MONGO_URI:
    log.error('CRITICAL: MONGO_URI environment variable is missing!')
DB_NAME = 'minex_license'

# Get MongoDB connection using Flask's application context
def get_db():
    """
    Returns MongoDB database connection from the Flask g object.
    Creates a new connection if none exists.
    """
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
            print(f'Error connecting to MongoDB: {e}')
            raise
    
    return g.mongo_client[DB_NAME]

# Close MongoDB connection when the application context ends
@app.teardown_appcontext
def close_mongo_connection(error):
    """Close MongoDB connection when the application context ends."""
    mongo_client = g.pop('mongo_client', None)
    if mongo_client is not None:
        mongo_client.close()

def init_db():
    """Initialize database collections and indexes."""
    # Get database connection
    db = get_db()
    
    # Initialize collections if they don't exist
    if 'users' not in db.list_collection_names():
        # Create users collection with unique index on username and api_key
        db.users.create_index('username', unique=True)
        db.users.create_index('api_key', unique=True)
        # Add index for numeric_id for migration support
        db.users.create_index('numeric_id')
    
    if 'tasks' not in db.list_collection_names():
        # Create tasks collection with unique index on task_id
        db.tasks.create_index('task_id', unique=True)
        # Add indexes for common queries
        db.tasks.create_index('api_key')
        db.tasks.create_index('status')
        db.tasks.create_index([('created_at', -1)])  # Descending index for sorting
    
    # Add indexes for other collections
    db.balance.create_index('user_id')
    db.transactions.create_index('user_id')
    db.transactions.create_index([('created_at', -1)])
    db.api_usage.create_index('api_key')
    db.api_usage.create_index([('timestamp', -1)])
    db.settings.create_index('key', unique=True)
    
    # Check if default settings exist, create them if not
    if db.settings.count_documents({}) == 0:
        # Insert default settings
        default_settings = [
            {
                'key': 'basic_cost_per_1k',
                'value': '3.0',
                'updated_at': time.time()
            },
            {
                'key': 'enterprise_cost_per_1k',
                'value': '5.0',
                'updated_at': time.time()
            },
            {
                'key': 'min_balance',
                'value': '0.0',
                'updated_at': time.time()
            }
        ]
        db.settings.insert_many(default_settings)

# Initialize balance for users
def ensure_user_balances():
    """Ensure all users have balance records."""
    # Get database connection
    db = get_db()
    
    # Find all users
    users = list(db.users.find())
    
    # Check if they have balance records, create if missing
    for user in users:
        balance = db.balance.find_one({'user_id': user['_id']})
        if not balance:
            db.balance.insert_one({
                'user_id': user['_id'],
                'amount': 0.0,
                'last_updated': time.time()
            })
            print(f"Created balance record for user {user['username']}")

# Add this migration function after init_db but before ensure_user_balances
def migrate_numeric_ids():
    """
    Store the original numeric ID from SQLite in MongoDB documents to aid with transition.
    This helps when user sessions still have the numeric IDs from SQLite.
    """
    # Get database connection
    db = get_db()
    
    # Check if migration has been done
    if db.settings.find_one({'key': 'migration_completed'}):
        return
    
    users = list(db.users.find())
    for i, user in enumerate(users, 1):
        # Add a numeric_id field if not present
        if 'numeric_id' not in user:
            db.users.update_one(
                {'_id': user['_id']},
                {'$set': {'numeric_id': i}}
            )
            print(f"Added numeric_id {i} to user {user['username']}")
    
    # Mark migration as completed
    db.settings.update_one(
        {'key': 'migration_completed'},
        {'$set': {'value': 'true', 'updated_at': time.time()}},
        upsert=True
    )
    print("Numeric ID migration completed")

# Initialize the database at application startup
with app.app_context():
    init_db()
    migrate_numeric_ids()
    ensure_user_balances()

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        
        # Validate that the user_id in session is valid
        user_id = safe_object_id(session['user_id'])
        if user_id is None:
            session.clear()
            return redirect(url_for('login', next=request.url))
            
        return f(*args, **kwargs)
    return decorated_function

# Utility functions
def safe_object_id(id_str):
    """Safely convert a string to ObjectId, returning None if invalid."""
    try:
        return ObjectId(id_str)
    except:
        return None

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # First check if user is logged in
        if 'user_id' not in session:
            return redirect(url_for('login', next=request.url))
        
        # Get the user from the database directly
        try:
            db = get_db()
            user_id = safe_object_id(session['user_id'])
            
            if not user_id:
                flash('Invalid user ID', 'error')
                return redirect(url_for('dashboard'))
                
            user = db.users.find_one({'_id': user_id})
            
            if not user:
                flash('User not found', 'error')
                return redirect(url_for('dashboard'))
                
            # Ensure the is_admin is stored as integer 1 for admins, 0 for non-admins
            is_admin_value = int(user.get('is_admin', 0))
            
            # Update session value for consistency
            session['is_admin'] = is_admin_value
            
            # Check if is_admin is 1
            if is_admin_value != 1:
                flash('Admin access required', 'error')
                return redirect(url_for('dashboard'))
                
            # If we get here, user is admin
            return f(*args, **kwargs)
            
        except Exception as e:
            print(f"Admin check error: {e}")
            flash('Error checking admin status', 'error')
            return redirect(url_for('dashboard'))
    
    return decorated_function

@app.route('/')
def index():
    return jsonify({'error': 'use frontend'})

# ========== JWT API ENDPOINTS (for static frontend) ==========

def jwt_required(f):
    """Decorator to protect API routes with JWT token verification."""
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

def create_jwt(user):
    """Generate a JWT token for a user."""
    payload = {
        'user_id': str(user['_id']),
        'username': user['username'],
        'is_admin': int(user.get('is_admin', 0)),
        'exp': time.time() + JWT_EXPIRY
    }
    return pyjwt.encode(payload, JWT_SECRET, algorithm='HS256')

@app.route('/api/login', methods=['POST'])
@csrf.exempt
@limiter.limit("10 per minute")
def api_login():
    db = get_db()
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'JSON body required'})
    
    username = bleach.clean(data.get('username', ''))
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'})
    
    user = db.users.find_one({'username': username})
    if not user or not bcrypt.checkpw(password.encode('utf-8'), user['password'].encode('utf-8')):
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})
    
    db.users.update_one({'_id': user['_id']}, {'$set': {'last_login': time.time()}})
    token = create_jwt(user)
    
    return jsonify({
        'status': 'success',
        'token': token,
        'user': {
            'username': user['username'],
            'api_key': user['api_key'],
            'is_admin': int(user.get('is_admin', 0))
        }
    })

@app.route('/api/register', methods=['POST'])
@csrf.exempt
@limiter.limit("5 per minute")
def api_register():
    db = get_db()
    data = request.json
    if not data:
        return jsonify({'status': 'error', 'message': 'JSON body required'})
    
    username = bleach.clean(data.get('username', ''))
    password = data.get('password', '')
    
    if not username or not password:
        return jsonify({'status': 'error', 'message': 'Username and password required'})
    
    if len(username) < 3:
        return jsonify({'status': 'error', 'message': 'Username must be at least 3 characters'})
    
    if len(password) < 6:
        return jsonify({'status': 'error', 'message': 'Password must be at least 6 characters'})
    
    if db.users.find_one({'username': username}):
        return jsonify({'status': 'error', 'message': 'Username already exists'})
    
    api_key = str(uuid.uuid4())
    hashed = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())
    is_admin = 1 if username.lower() == 'admin' else 0
    
    try:
        result = db.users.insert_one({
            'username': username,
            'password': hashed.decode('utf-8'),
            'api_key': api_key,
            'created_at': time.time(),
            'last_login': time.time(),
            'is_admin': is_admin
        })
        db.balance.insert_one({'user_id': result.inserted_id, 'amount': 0.0, 'last_updated': time.time()})
        
        user = db.users.find_one({'_id': result.inserted_id})
        token = create_jwt(user)
        
        return jsonify({
            'status': 'success',
            'token': token,
            'user': {
                'username': user['username'],
                'api_key': user['api_key'],
                'is_admin': is_admin
            }
        })
    except Exception as e:
        return jsonify({'status': 'error', 'message': f'Registration failed: {str(e)}'})

@app.route('/api/session', methods=['GET'])
@csrf.exempt
@jwt_required
def api_session():
    db = get_db()
    user_id = safe_object_id(request.jwt_user_id)
    user = db.users.find_one({'_id': user_id})
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'}), 404
    
    balance_doc = db.balance.find_one({'user_id': user['_id']})
    balance = balance_doc['amount'] if balance_doc else 0.0
    
    return jsonify({
        'status': 'success',
        'user': {
            'username': user['username'],
            'api_key': user['api_key'],
            'is_admin': int(user.get('is_admin', 0)),
            'balance': balance
        }
    })

# ========== END JWT API ENDPOINTS ==========

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))

@app.route('/admin/users')
@admin_required
def users_management():
    try:
        db = get_db()
        # Get all users with pagination
        page = request.args.get('page', 1, type=int)
        per_page = 20
        skip = (page - 1) * per_page
        
        # Use aggregation for more efficient user data retrieval with projection
        users_pipeline = [
            {"$sort": {"created_at": -1}},
            {"$skip": skip},
            {"$limit": per_page},
            {"$project": {
                "_id": 1,
                "username": 1,
                "email": 1,
                "created_at": 1,
                "is_admin": {"$ifNull": ["$is_admin", False]},
                "is_active": {"$ifNull": ["$is_active", True]},
                "api_key": 1
            }}
        ]
        
        users = list(db.users.aggregate(users_pipeline))
        
        # Get total count for pagination
        total_users = db.users.count_documents({})
        total_pages = math.ceil(total_users / per_page)
        
        # Get balance for each user and add to user object
        for user in users:
            balance = db.balance.find_one({"user_id": user["_id"]})
            user["balance"] = balance.get("amount", 0) if balance else 0
            
            # Convert ObjectId to string for JSON serialization
            user["_id"] = str(user["_id"])
            
            # Format timestamps
            if "created_at" in user:
                user["created_at_formatted"] = datetime.fromtimestamp(user["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
        
        return render_template('admin/users.html', 
                              users=users, 
                              page=page, 
                              total_pages=total_pages)
    except Exception as e:
        print(f"Error in users management: {e}")
        flash(f"An error occurred: {str(e)}", "danger")
        return jsonify({'status': 'error', 'message': 'Legacy route removed'})

@app.route('/admin/user/<user_id>', methods=['GET', 'POST'])
@admin_required
def user_details(user_id):
    try:
        db = get_db()
        # Convert string user_id to ObjectId
        user_id_obj = safe_object_id(user_id)
        if not user_id_obj:
            flash("Invalid user ID format", "danger")
            return redirect(url_for('users_management'))
        
        # Find user by ID
        user = db.users.find_one({"_id": user_id_obj})
        if not user:
            flash("User not found", "danger")
            return redirect(url_for('users_management'))
        
        if request.method == 'POST':
            # Update user fields from form
            update_data = {
                "username": request.form.get('username'),
                "email": request.form.get('email'),
                "is_active": bool(request.form.get('is_active')),
                "is_admin": bool(request.form.get('is_admin'))
            }
            
            # Update balance if provided
            new_balance = request.form.get('balance')
            if new_balance is not None and new_balance.strip():
                try:
                    new_balance_float = float(new_balance)
                    
                    # Use upsert to create balance document if it doesn't exist
                    db.balance.update_one(
                        {"user_id": user_id_obj},
                        {"$set": {"amount": new_balance_float}},
                        upsert=True
                    )
                except ValueError:
                    flash("Invalid balance value", "danger")
            
            # Update user document
            result = db.users.update_one(
                {"_id": user_id_obj},
                {"$set": update_data}
            )
            
            if result.modified_count > 0:
                flash("User updated successfully", "success")
            else:
                flash("No changes were made", "info")
                
            return redirect(url_for('user_details', user_id=user_id))
        
        # Get user balance
        balance = db.balance.find_one({"user_id": user_id_obj})
        balance_amount = balance.get("amount", 0) if balance else 0
        
        # Get recent transactions for this user with aggregation
        transactions_pipeline = [
            {"$match": {"user_id": user_id_obj}},
            {"$sort": {"created_at": -1}},
            {"$limit": 10},
            {"$project": {
                "amount": 1,
                "type": 1,
                "description": 1,
                "created_at": 1
            }}
        ]
        
        transactions = list(db.transactions.aggregate(transactions_pipeline))
        
        # Format transactions for display
        for transaction in transactions:
            transaction["created_at_formatted"] = datetime.fromtimestamp(transaction["created_at"]).strftime("%Y-%m-%d %H:%M:%S")
            
        return render_template('admin/user_details.html', 
                              user=user, 
                              balance=balance_amount,
                              transactions=transactions)
    except Exception as e:
        print(f"Error in user details: {e}")
        flash(f"An error occurred: {str(e)}", "danger")
        return redirect(url_for('users_management'))

@app.route('/admin/add_balance', methods=['POST'])
@admin_required
def admin_add_balance():
    db = get_db()
    user_id = request.form.get('user_id')
    amount = float(request.form.get('amount', 0))
    description = request.form.get('description', 'Admin credit')
    
    if not user_id or amount <= 0:
        flash('Invalid input', 'error')
        return redirect(url_for('users_management'))
    
    # Get current balance
    balance_result = db.balance.find_one({'user_id': ObjectId(user_id)})
    
    if not balance_result:
        # Create balance record if it doesn't exist
        db.balance.insert_one({'user_id': ObjectId(user_id), 'amount': amount, 'last_updated': time.time()})
        new_balance = amount
    else:
        # Update existing balance
        new_balance = balance_result['amount'] + amount
        db.balance.update_one(
            {'_id': balance_result['_id']},
            {'$set': {'amount': new_balance, 'last_updated': time.time()}}
        )
    
    # Add transaction record
    db.transactions.insert_one({
        'user_id': ObjectId(user_id),
        'amount': amount,
        'type': 'credit',
        'description': description,
        'created_at': time.time()
    })
    
    flash(f'Added {amount} credits to user {user_id}', 'success')
    return redirect(url_for('users_management'))

@app.route('/admin/settings', methods=['GET', 'POST'])
@admin_required
def admin_settings():
    db = get_db()
    if request.method == 'POST':
        basic_cost = float(request.form.get('basic_cost_per_1k', 3.0))
        enterprise_cost = float(request.form.get('enterprise_cost_per_1k', 5.0))
        min_balance = float(request.form.get('min_balance', 0.0))
        
        # Update settings
        db.settings.update_one(
            {'key': 'basic_cost_per_1k'},
            {'$set': {'value': str(basic_cost), 'updated_at': time.time()}}
        )
        
        db.settings.update_one(
            {'key': 'enterprise_cost_per_1k'},
            {'$set': {'value': str(enterprise_cost), 'updated_at': time.time()}}
        )
        
        db.settings.update_one(
            {'key': 'min_balance'},
            {'$set': {'value': str(min_balance), 'updated_at': time.time()}}
        )
        
        flash('Settings updated successfully', 'success')
        return redirect(url_for('admin_settings'))
    
    # Get settings
    settings = {}
    for setting in db.settings.find():
        settings[setting['key']] = setting['value']
    
    return jsonify({'status': 'error', 'message': 'Legacy route removed'})

# Dashboard API endpoints
@app.route('/get_user_info', methods=['POST'])
@csrf.exempt
def get_user_info():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Get user details based on API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    return jsonify({
        'status': 'success',
        'username': user['username']
    })

@app.route('/session_info', methods=['GET'])
@login_required
@csrf.exempt
def session_info():
    return jsonify({
        'status': 'success',
        'username': session.get('username', 'User'),
        'is_admin': session.get('is_admin', 0)
    })

@app.route('/get_api_key', methods=['GET'])
@login_required
@csrf.exempt
def get_api_key():
    db = get_db()
    # Get user's API key
    user_id = safe_object_id(session['user_id'])
    user = db.users.find_one({'_id': user_id})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'User not found'})
    
    return jsonify({
        'status': 'success',
        'api_key': user['api_key']
    })

@app.route('/get_balance', methods=['POST'])
@csrf.exempt
def get_balance():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Get user ID from API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get balance from balance collection
    balance_doc = db.balance.find_one({'user_id': user['_id']})
    
    if not balance_doc:
        # If no balance record exists, create one with default value
        balance = 0.0
        db.balance.insert_one({
            'user_id': user['_id'], 
            'amount': balance,
            'last_updated': time.time()
        })
    else:
        balance = balance_doc['amount']
    
    return jsonify({
        'status': 'success',
        'balance': balance
    })

@app.route('/get_daily_usage', methods=['POST'])
@csrf.exempt
def get_daily_usage():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Verify API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get daily usage from tasks collection
    current_time = time.time()
    day_ago = current_time - 24*3600
    
    daily_requests = db.api_usage.count_documents({
        'api_key': api_key,
        'timestamp': {'$gte': day_ago}
    })
    
    return jsonify({
        'status': 'success',
        'daily_requests': daily_requests
    })

@app.route('/get_success_rate', methods=['POST'])
@csrf.exempt
def get_success_rate():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    
    # Verify API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get success rate from tasks collection
    solved_count = db.tasks.count_documents({
        'api_key': api_key,
        'status': 'solved'
    })
    
    total_count = db.tasks.count_documents({
        'api_key': api_key,
        'status': {'$in': ['solved', 'error']}
    })
    
    # Calculate success rate
    success_rate = 0
    if total_count > 0:
        success_rate = (solved_count / total_count) * 100
    
    return jsonify({
        'status': 'success',
        'success_rate': success_rate
    })

@app.route('/get_recent_tasks', methods=['POST'])
@csrf.exempt
def get_recent_tasks():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    limit = data.get('limit', 5)  # Default to 5 recent tasks
    
    # Verify API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get recent tasks from database
    tasks = list(db.tasks.find(
        {'api_key': api_key},
        {'_id': 0, 'task_id': 1, 'task_type': 1, 'status': 1, 'created_at': 1}
    ).sort('created_at', -1).limit(limit))
    
    # Format tasks for response
    formatted_tasks = []
    for task in tasks:
        formatted_tasks.append({
            'id': task['task_id'],
            'type': task['task_type'],
            'status': task['status'],
            'timestamp': task['created_at']
        })
    
    return jsonify({
        'status': 'success',
        'tasks': formatted_tasks
    })

@app.route('/get_task_history', methods=['POST'])
@csrf.exempt
def get_task_history():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    page = data.get('page', 1)
    date_filter = data.get('date_filter', 'all')
    status_filter = data.get('status_filter', 'all')
    
    # Verify API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Build query based on filters
    query = {'api_key': api_key}
    
    # Apply date filter
    current_time = time.time()
    if date_filter == 'today':
        query['created_at'] = {'$gte': current_time - 24*3600}  # Last 24 hours
    elif date_filter == 'yesterday':
        query['created_at'] = {
            '$gte': current_time - 48*3600,  # 24-48 hours ago
            '$lt': current_time - 24*3600
        }
    elif date_filter == 'week':
        query['created_at'] = {'$gte': current_time - 7*24*3600}  # Last 7 days
    elif date_filter == 'month':
        query['created_at'] = {'$gte': current_time - 30*24*3600}  # Last 30 days
    
    # Apply status filter
    if status_filter != 'all':
        query['status'] = status_filter
    
    # Get total count for pagination
    total_tasks = db.tasks.count_documents(query)
    
    # Apply pagination
    per_page = 10
    total_pages = (total_tasks + per_page - 1) // per_page
    
    if page < 1 or page > total_pages:
        page = 1
    
    skip = (page - 1) * per_page
    
    # Get paginated tasks
    tasks = list(db.tasks.find(
        query,
        {'_id': 0, 'task_id': 1, 'task_type': 1, 'status': 1, 'created_at': 1}
    ).sort('created_at', -1).skip(skip).limit(per_page))
    
    # Format tasks for response
    formatted_tasks = []
    for task in tasks:
        formatted_tasks.append({
            'id': task['task_id'],
            'type': task['task_type'],
            'status': task['status'],
            'timestamp': task['created_at'],
            'details': f"Task details for {task['task_id']}"
        })
    
    return jsonify({
        'status': 'success',
        'tasks': formatted_tasks,
        'total_pages': total_pages,
        'current_page': page
    })

@app.route('/reset_key', methods=['POST'])
@login_required
@csrf.exempt
def reset_key():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'Current API key is required'})
    
    # Generate a new API key as UUID (GUID)
    new_key = str(uuid.uuid4())
    
    # Update the API key in the database
    user_id = safe_object_id(session['user_id'])
    if user_id:
        db.users.update_one(
            {'_id': user_id}, 
            {'$set': {'api_key': new_key}}
        )
    
    return jsonify({
        'status': 'success',
        'new_key': new_key
    })

@app.route('/get_transactions', methods=['POST'])
@csrf.exempt
def get_transactions():
    db = get_db()
    data = request.json
    if not data or 'key' not in data:
        return jsonify({'status': 'error', 'message': 'API key is required'})
    
    api_key = data['key']
    limit = data.get('limit', 10)  # Default to 10 transactions
    
    # Verify API key
    user = db.users.find_one({'api_key': api_key})
    
    if not user:
        return jsonify({'status': 'error', 'message': 'Invalid API key'})
    
    # Get transactions from database
    transactions = list(db.transactions.find(
        {'user_id': user['_id']},
        {'_id': 0, 'amount': 1, 'type': 1, 'description': 1, 'created_at': 1}
    ).sort('created_at', -1).limit(limit))
    
    # Format transactions for response
    formatted_transactions = []
    for transaction in transactions:
        formatted_transactions.append({
            'amount': transaction['amount'],
            'type': transaction['type'],
            'description': transaction['description'],
            'timestamp': transaction['created_at']
        })
    
    return jsonify({
        'status': 'success',
        'transactions': formatted_transactions
    })

# API Key Validation Functions
def validate_api_key(api_key):
    try:
        db = get_db()
        user = db.users.find_one({'api_key': api_key})
        
        if not user:
            return False, "Invalid API key"
        
        return True, "Valid API key"
    except Exception as e:
        return False, str(e)

def get_task_cost(task_type='hcaptcha_basic'):
    try:
        db = get_db()
        cost_key = 'basic_cost_per_1k' if task_type == 'hcaptcha_basic' else 'enterprise_cost_per_1k'
        setting = db.settings.find_one({'key': cost_key})
        
        if not setting:
            # Default costs
            default_costs = {
                'hcaptcha_basic': 3.0,
                'enterprise': 5.0
            }
            return default_costs.get(task_type, 3.0) / 1000  # Cost per single solve
        
        # Convert from cost per 1k to cost per single solve
        return float(setting['value']) / 1000
    except Exception as e:
        print(f"Error getting task cost: {e}")
        # Default costs per single solve
        default_costs = {
            'hcaptcha_basic': 0.003,
            'enterprise': 0.005
        }
        return default_costs.get(task_type, 0.003)

def increment_api_key_usage(api_key, task_type='hcaptcha_basic'):
    try:
        db = get_db()
        # Insert usage record in MongoDB with error handling
        try:
            db.api_usage.insert_one({
                'api_key': api_key,
                'timestamp': time.time(),
                'task_type': task_type
            })
        except Exception as e:
            print(f"Error recording API usage: {e}")
            # Continue anyway, don't fail the task
        
        # Get daily usage count for metrics
        day_ago = time.time() - 24*3600
        try:
            daily_count = db.api_usage.count_documents({
                'api_key': api_key,
                'timestamp': {'$gte': day_ago}
            })
            return True
        except Exception as e:
            print(f"Error counting daily usage: {e}")
            return False
    except Exception as e:
        print(f"Error incrementing API key usage: {e}")
        return False

# Solver Class
class Solver:
    def __init__(self, api_key):
        self.api_key = api_key
        
    def solve(self, sitekey, siteurl, proxy=None, rqdata=None):
        try:
            # Validate API key
            valid, message = validate_api_key(self.api_key)
            if not valid:
                return "error_" + message
            
            # Create and solve captcha using the new solver
            captcha = hcaptcha(sitekey, siteurl, proxy, rqdata)
            result = captcha.solve()
            
            if result is None:
                return "error"
            
            # Increment API key usage
            increment_api_key_usage(self.api_key)
            
            return result
        except Exception as e:
            print(f"Error solving captcha: {e}")
            return "error"
    
    def create_task(self, task_type, sitekey, siteurl, proxy=None, rqdata=None):
        try:
            db = get_db()
            # Validate API key
            valid, message = validate_api_key(self.api_key)
            if not valid:
                return False, message
            
            # Get user from API key
            user = db.users.find_one({'api_key': self.api_key})
            
            if not user:
                return False, "Invalid API key"
            
            # Get user's balance
            balance_doc = db.balance.find_one({'user_id': user['_id']})
            
            # Get task cost from settings based on task type
            task_cost = get_task_cost(task_type)
            
            if not balance_doc or balance_doc['amount'] < task_cost:
                return False, "Insufficient balance"
            
            # Deduct balance
            new_balance = balance_doc['amount'] - task_cost
            
            db.balance.update_one(
                {'user_id': user['_id']},
                {'$set': {'amount': new_balance, 'last_updated': time.time()}}
            )
            
            # Add transaction record
            db.transactions.insert_one({
                'user_id': user['_id'],
                'amount': -task_cost,
                'type': 'debit',
                'description': f'Task: {task_type}',
                'created_at': time.time()
            })
            
            # Generate a unique task ID
            task_id = str(uuid.uuid4())
            
            # Store in database
            db.tasks.insert_one({
                'task_id': task_id,
                'api_key': self.api_key,
                'task_type': task_type,
                'sitekey': sitekey,
                'siteurl': siteurl,
                'proxy': proxy,
                'rqdata': rqdata,
                'status': 'solving',
                'created_at': time.time()
            })
            
            # Start a thread to solve the captcha
            thread = threading.Thread(
                target=self._task_solver,
                args=(task_id, task_type, sitekey, siteurl, proxy, rqdata)
            )
            
            # Start the thread
            thread.daemon = True
            thread.start()
            
            return True, task_id
        except Exception as e:
            print(f"Error creating task: {e}")
            return False, str(e)
    
    def _task_solver(self, task_id, task_type, sitekey, siteurl, proxy, rqdata):
        """
        Solves a captcha task in a separate thread.
        Handles database connections properly within the thread context.
        """
        try:
            # Create a new database connection for this thread
            g.mongo_client = MongoClient(
                MONGO_URI,
                serverSelectionTimeoutMS=5000,
                connectTimeoutMS=10000,
                socketTimeoutMS=45000,
                maxPoolSize=50,
                retryWrites=True,
                tlsAllowInvalidCertificates=True  # Ensure this is explicitly set
            )
            # Connection will be established on first command
            db = g.mongo_client[DB_NAME]
            
            # Create and solve captcha using the solver
            captcha = hcaptcha(sitekey, siteurl, proxy, rqdata)
            result = captcha.solve()
            
            # Update task in database
            if result is None:
                db.tasks.update_one(
                    {'task_id': task_id},
                    {'$set': {
                        'status': 'error',
                        'error': 'Failed to solve captcha'
                    }}
                )
            else:
                db.tasks.update_one(
                    {'task_id': task_id},
                    {'$set': {
                        'status': 'solved',
                        'solution': result
                    }}
                )
                
                # Increment API key usage on successful solve with task type
                try:
                    db.api_usage.insert_one({
                        'api_key': self.api_key,
                        'timestamp': time.time(),
                        'task_type': task_type
                    })
                except Exception as e:
                    print(f"Error recording API usage in thread: {e}")
                    
        except Exception as e:
            try:
                # Attempt to update task with error
                db.tasks.update_one(
                    {'task_id': task_id},
                    {'$set': {
                        'status': 'error',
                        'error': str(e)
                    }}
                )
            except Exception as update_error:
                print(f"Error updating task status: {update_error}")
        finally:
            # Always close the database connection
            try:
                client.close()
            except Exception as e:
                print(f"Error closing database connection: {e}")
    
    def get_task_solution(self, task_id):
        try:
            db = get_db()
            task = db.tasks.find_one({'task_id': task_id})
            
            if not task:
                return "not_found", None
            
            # Verify that the API key matches the task
            if task['api_key'] != self.api_key:
                return "unauthorized", None
            
            if task['status'] == "solving":
                return "solving", None
            elif task['status'] == "error":
                return "error", task.get('error')
            elif task['status'] == "solved":
                return "solved", task.get('solution')
            
            return "unknown", None
        except Exception as e:
            print(f"Error getting task solution: {e}")
            return "error", str(e)

# API Endpoints
@app.route('/create_task', methods=['POST'])
@csrf.exempt
def create_task():
    data = request.json
    
    if not data:
        return jsonify({"status": "error", "message": "No data provided"}), 400
    
    api_key = data.get('key')
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    task_type = data.get('type', 'hcaptcha_basic')
    if task_type not in ['hcaptcha_basic', 'enterprise']:
        return jsonify({"status": "error", "message": "Invalid task type"}), 400
    
    task_data = data.get('data', {})
    if not task_data:
        return jsonify({"status": "error", "message": "Task data is required"}), 400
    
    sitekey = task_data.get('sitekey')
    if not sitekey:
        return jsonify({"status": "error", "message": "Site key is required"}), 400
    
    siteurl = task_data.get('siteurl', 'discord.com')
    proxy = task_data.get('proxy', '')
    rqdata = task_data.get('rqdata')
    
    solver = Solver(api_key)
    success, result = solver.create_task(task_type, sitekey, siteurl, proxy, rqdata)
    
    if not success:
        return jsonify({"status": "error", "message": result}), 500
    
    return jsonify({"status": "success", "task_id": result})

@app.route('/get_result/<task_id>', methods=['GET'])
@csrf.exempt
def get_result(task_id):
    # For GET requests, look for API key in query parameters
    api_key = request.args.get('key')
    
    # If not in query parameters, try JSON data (backwards compatibility)
    if not api_key and request.is_json:
        data = request.json
        if data and 'key' in data:
            api_key = data['key']
    
    if not api_key:
        return jsonify({"status": "error", "message": "API key is required"}), 400
    
    solver = Solver(api_key)
    status, result = solver.get_task_solution(task_id)
    
    if status == "not_found":
        return jsonify({"status": "error", "message": "Task not found"}), 404
    elif status == "unauthorized":
        return jsonify({"status": "error", "message": "Unauthorized"}), 403
    elif status == "solving":
        return jsonify({"status": "solving"})
    elif status == "error":
        return jsonify({"status": "error", "message": result}), 500
    elif status == "solved":
        return jsonify({"status": "success", "solution": result})
    
    return jsonify({"status": "error", "message": "Unknown error"}), 500

# Admin routes
@app.route('/admin_add_credits', methods=['POST'])
@admin_required
def admin_add_credits():
    db = get_db()
    user_id = request.form.get('user_id')
    amount = float(request.form.get('amount', 0))
    
    if not user_id or amount <= 0:
        flash('Invalid input', 'error')
        return redirect(url_for('users_management'))
    
    # Convert user_id to ObjectId safely
    object_id = safe_object_id(user_id)
    if not object_id:
        flash('Invalid user ID', 'error')
        return redirect(url_for('users_management'))
    
    # Get current balance
    balance_doc = db.balance.find_one({'user_id': object_id})
    
    if not balance_doc:
        # Create balance record if it doesn't exist
        db.balance.insert_one({
            'user_id': object_id,
            'amount': amount,
            'last_updated': time.time()
        })
        new_balance = amount
    else:
        # Update existing balance
        new_balance = balance_doc['amount'] + amount
        db.balance.update_one(
            {'_id': balance_doc['_id']},
            {'$set': {'amount': new_balance, 'last_updated': time.time()}}
        )
    
    # Add transaction record
    db.transactions.insert_one({
        'user_id': object_id,
        'amount': amount,
        'type': 'credit',
        'description': 'Admin credit',
        'created_at': time.time()
    })
    
    flash(f'Added {amount} credits to user {user_id}', 'success')
    return redirect(url_for('users_management'))

@app.route('/admin_reset_api_key', methods=['POST'])
@admin_required
def admin_reset_api_key():
    db = get_db()
    user_id = request.form.get('user_id')
    
    if not user_id:
        flash('Invalid user ID', 'error')
        return redirect(url_for('users_management'))
    
    # Convert user_id to ObjectId safely
    object_id = safe_object_id(user_id)
    if not object_id:
        flash('Invalid user ID format', 'error')
        return redirect(url_for('users_management'))
    
    # Generate new API key as UUID (GUID)
    new_key = str(uuid.uuid4())
    
    # Update user's API key
    db.users.update_one(
        {'_id': object_id},
        {'$set': {'api_key': new_key}}
    )
    
    flash(f'API key reset for user {user_id}', 'success')
    return redirect(url_for('users_management'))

@app.route('/admin_delete_user', methods=['POST'])
@admin_required
def admin_delete_user():
    db = get_db()
    user_id = request.form.get('user_id')
    
    if not user_id:
        flash('Invalid user ID', 'error')
        return redirect(url_for('users_management'))
    
    # Convert session user_id and requested user_id to ObjectId safely
    session_user_object_id = safe_object_id(session['user_id'])
    object_id = safe_object_id(user_id)
    
    if not object_id:
        flash('Invalid user ID format', 'error')
        return redirect(url_for('users_management'))
    
    # Prevent deleting yourself
    if session_user_object_id and object_id == session_user_object_id:
        flash('You cannot delete your own account', 'error')
        return redirect(url_for('users_management'))
    
    # Get user's API key for deleting related records
    user = db.users.find_one({'_id': object_id})
    
    if user:
        # Delete user's records
        db.balance.delete_many({'user_id': object_id})
        db.transactions.delete_many({'user_id': object_id})
        db.tasks.delete_many({'api_key': user['api_key']})
        db.api_usage.delete_many({'api_key': user['api_key']})
        
        # Delete user
        db.users.delete_one({'_id': object_id})
    
    flash(f'User {user_id} deleted successfully', 'success')
    return redirect(url_for('users_management'))

@app.route('/admin_update_settings', methods=['POST'])
@admin_required
def admin_update_settings():
    db = get_db()
    # Get form data
    allow_registration = 'allow_registration' in request.form
    require_captcha = 'require_captcha' in request.form
    enable_api = 'enable_api' in request.form
    default_credits = float(request.form.get('default_credits', 0))
    credit_cost = float(request.form.get('credit_cost', 0))
    
    # Update settings
    settings_to_update = {
        'allow_registration': str(int(allow_registration)),
        'require_captcha': str(int(require_captcha)),
        'enable_api': str(int(enable_api)),
        'default_credits': str(default_credits),
        'credit_cost': str(credit_cost)
    }
    
    # Update each setting
    for key, value in settings_to_update.items():
        db.settings.update_one(
            {'key': key},
            {'$set': {'value': value, 'updated_at': time.time()}},
            upsert=True
        )
    
    flash('Settings updated successfully', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin_backup_database', methods=['POST'])
@admin_required
def admin_backup_database():
    # This would typically create a database backup file
    # For simplicity, we'll just send a success message
    flash('Database backup functionality would be implemented here', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/admin_reset_settings', methods=['POST'])
@admin_required
def admin_reset_settings():
    db = get_db()
    # Reset to default settings
    default_settings = {
        'allow_registration': '1',
        'require_captcha': '1',
        'enable_api': '1',
        'default_credits': '0.0',
        'credit_cost': '0.003',
        'basic_cost_per_1k': '3.0',
        'enterprise_cost_per_1k': '5.0',
        'min_balance': '0.0'
    }
    
    # Update each setting to default
    for key, value in default_settings.items():
        db.settings.update_one(
            {'key': key},
            {'$set': {'value': value, 'updated_at': time.time()}},
            upsert=True
        )
    
    flash('Settings have been reset to defaults', 'success')
    return redirect(url_for('admin_settings'))

@app.route('/task/<task_id>')
@login_required
def get_task_status(task_id):
    try:
        db = get_db()
        # Get user_id from session
        user_id = safe_object_id(session.get('user_id'))
        if not user_id:
            return jsonify({'error': 'Invalid session'}), 401
        
        # Get user API key
        user = db.users.find_one({'_id': user_id})
        if not user:
            return jsonify({'error': 'User not found'}), 404
            
        api_key = user.get('api_key')
        if not api_key:
            return jsonify({'error': 'API key not found'}), 404
            
        # Find task by ID and API key to ensure it belongs to this user
        task = db.tasks.find_one({'task_id': task_id, 'api_key': api_key})
        if not task:
            return jsonify({'error': 'Task not found or not authorized'}), 404
            
        # Prepare response data
        response_data = {
            'status': task.get('status', 'unknown'),
            'created_at': task.get('created_at', 0),
            'task_type': task.get('task_type', 'unknown')
        }
        
        # Add results if task is completed
        if task.get('status') == 'completed':
            response_data['results'] = task.get('results', {})
            
        return jsonify(response_data)
    except Exception as e:
        print(f"Error fetching task status: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

@app.route('/api/hcaptcha')
def api_hcaptcha():
    try:
        db = get_db()
        start_time = time.time()
        api_key = request.args.get('api_key')
        num_tasks = int(request.args.get('num_tasks', 1))
        
        # Validate API key
        if not api_key:
            return jsonify({'error': 'API key is required'}), 400
            
        user = db.users.find_one({'api_key': api_key})
        if not user:
            return jsonify({'error': 'Invalid API key'}), 401
        
        # Check user balance
        user_id = user['_id']
        balance = db.balance.find_one({'user_id': user_id})
        
        # Verify sufficient balance
        task_cost = 0.5  # Cost per task
        total_cost = task_cost * num_tasks
        
        if not balance or float(balance.get('amount', 0)) < total_cost:
            return jsonify({'error': 'Insufficient balance'}), 402
            
        # Deduct credits from balance
        try:
            db.balance.update_one(
                {'user_id': user_id},
                {'$inc': {'amount': -total_cost}}
            )
            
            # Record transaction
            db.transactions.insert_one({
                'user_id': user_id,
                'amount': -total_cost,
                'type': 'debit',
                'description': f'API usage: {num_tasks} hCaptcha task(s)',
                'created_at': time.time()
            })
        except Exception as e:
            print(f"Error updating balance: {e}")
            return jsonify({'error': 'Failed to update balance'}), 500
            
        # Create task and record usage
        task_id = str(uuid.uuid4())
        increment_api_key_usage(api_key, 'hcaptcha_basic')
        
        # Store task in database
        db.tasks.insert_one({
            'task_id': task_id,
            'api_key': api_key,
            'user_id': user_id,
            'task_type': 'hcaptcha_basic',
            'num_tasks': num_tasks,
            'cost': total_cost,
            'status': 'processing',
            'created_at': time.time()
        })
        
        # Process the task asynchronously
        # Note: Implementation of process_hcaptcha_task function needs to be added
        threading.Thread(target=process_hcaptcha_task, args=(task_id, num_tasks)).start()
        
        return jsonify({
            'task_id': task_id,
            'status': 'processing',
            'created_at': time.time(),
            'processing_time': time.time() - start_time
        })
    except Exception as e:
        print(f"API hCaptcha error: {e}")
        return jsonify({'error': f'Internal server error: {str(e)}'}), 500

# Define the process_hcaptcha_task function (missing in original code)
def process_hcaptcha_task(task_id, num_tasks):
    """
    Process hCaptcha tasks asynchronously.
    This function should be implemented to handle the actual captcha solving.
    """
    try:
        db = get_db()
        # Simulate processing time
        time.sleep(5)  # Replace with actual processing
        
        # Update task status
        db.tasks.update_one(
            {'task_id': task_id},
            {'$set': {
                'status': 'completed',
                'results': {
                    'success': True,
                    'solved': num_tasks,
                    'completed_at': time.time()
                }
            }}
        )
    except Exception as e:
        print(f"Error processing hCaptcha task: {e}")
        # Update task with error status
        try:
            db = get_db()
            db.tasks.update_one(
                {'task_id': task_id},
                {'$set': {
                    'status': 'error',
                    'error': str(e),
                    'completed_at': time.time()
                }}
            )
        except:
            pass  # If we can't even update the error status, just log and continue

# Add a compatibility route for admin_users to maintain backward compatibility with templates
