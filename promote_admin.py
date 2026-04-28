import os
from pymongo import MongoClient
from dotenv import load_dotenv

load_dotenv()
MONGO_URI = os.environ.get('MONGO_URI')
client = MongoClient(MONGO_URI)
db = client['minex_license']

# Ensure 'admin' user is actually an admin
res = db.users.update_one({'username': 'admin'}, {'$set': {'is_admin': 1}})
if res.matched_count:
    print("User 'admin' found and promoted to Administrator.")
else:
    print("User 'admin' not found.")

# List all admins
admins = db.users.find({'is_admin': 1})
print("\nCurrent Administrators:")
for a in admins:
    print(f"- {a['username']}")
