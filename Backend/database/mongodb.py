from pymongo import MongoClient
import os

MONGO_URI = os.environ.get("mongodb+srv://GuardianAdmin:GNode@cluster0.ifqkmq1.mongodb.net/?appName=Cluster0")

if not MONGO_URI:

    raise Exception(
        "MONGO_URI environment variable not set"
    )

client = MongoClient(MONGO_URI)

db = client["guardiannode"]

users_collection = db["users"]

threats_collection = db["threats"]