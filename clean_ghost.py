from pymongo import MongoClient
import os
from dotenv import load_dotenv

load_dotenv('config.env')
uri = os.environ.get("MONGO_URI")
client = MongoClient(uri)
db = client.get_database('9captcha')

res = db.transactions.delete_many({'type': 'deposit_pending'})
print(f"Deleted {res.deleted_count} ghost pending transactions.")
