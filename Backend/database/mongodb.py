from pymongo import MongoClient
import certifi

MONGO_URI = "mongodb://GuardianAdmin:GNode@ac-gyoysxe-shard-00-00.ifqkmq1.mongodb.net:27017,ac-gyoysxe-shard-00-01.ifqkmq1.mongodb.net:27017,ac-gyoysxe-shard-00-02.ifqkmq1.mongodb.net:27017/?ssl=true&replicaSet=atlas-c7hxy6-shard-0&authSource=admin&appName=Cluster0"

client = MongoClient(
    MONGO_URI,
    tls=True,
    tlsCAFile=certifi.where(),
    tlsInsecure=True
)

db = client["guardiannode"]

users_collection = db["users"]