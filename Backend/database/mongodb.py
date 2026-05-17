from pymongo import MongoClient

client = MongoClient("mongodb://localhost:27017/")

db = client["guardiannode"]

users_collection = db["users"]
threats_collection = db["threats"]