import pymongo
try:
    c = pymongo.MongoClient("mongodb+srv://operators129_db_user:FNhe23HESNUthP3V@minexaiolisence.keqvult.mongodb.net/?retryWrites=true&w=majority&appName=MineXAIOLisence")
    db = c['minex_license']
    db.balance.update_many({}, {'$set': {'amount': 100000.0}})
    print("Balance refilled")
except Exception as e:
    print(e)
