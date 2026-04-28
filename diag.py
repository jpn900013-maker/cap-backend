import os
from pymongo import MongoClient
from dotenv import load_dotenv
import time

load_dotenv()
MONGO_URI = os.environ.get('MONGO_URI')
client = MongoClient(MONGO_URI)
db = client['minex_license']

# Get the admin user 'gg'
user = db.users.find_one({'username': 'gg'})
if not user:
    print("User 'gg' not found.")
    exit()

api_key = user['api_key']
print(f"Diagnostics for user: {user['username']}")
print(f"API Key: {api_key}")

# Check tasks
total_tasks = db.tasks.count_documents({'api_key': api_key})
total_solves = db.tasks.count_documents({'api_key': api_key, 'status': 'solved'})
other_statuses = db.tasks.distinct('status', {'api_key': api_key})

print(f"Total Tasks in DB: {total_tasks}")
print(f"Total Solves in DB: {total_solves}")
print(f"Distinct Statuses: {other_statuses}")

# Check usage
usage_24h = db.api_usage.count_documents({
    'api_key': api_key,
    'timestamp': {'$gt': time.time() - 86400}
})
print(f"Usage 24h: {usage_24h}")

# Sample task
sample_task = db.tasks.find_one({'api_key': api_key})
if sample_task:
    print(f"Sample task data: {sample_task}")
else:
    print("No tasks found for this API key.")
