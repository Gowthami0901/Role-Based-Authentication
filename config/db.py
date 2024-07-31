 
from pymongo import MongoClient
from decouple import config

MONGO_URI = config("MONGO_URI", default="mongodb://localhost:27017/")

client = MongoClient(MONGO_URI)
db = client.local  # 'local' is the name of the database
user_collection = db.user  # mongodb://localhost:27017/local.user


# # Print all users
# for user in user_collection.find():
#     print(user)
