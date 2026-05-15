from database.mongodb import users_collection

class UserModel:

    @staticmethod
    def create_user(user_data):
        return users_collection.insert_one(user_data)

    @staticmethod
    def find_by_email(email):
        return users_collection.find_one({
            "email": email
        })