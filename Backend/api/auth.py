from flask import Blueprint, request, jsonify
from models.user_model import UserModel
from flask_jwt_extended import create_access_token
import bcrypt

auth_bp = Blueprint("auth", __name__)

# REGISTER
@auth_bp.route("/register", methods=["POST"])
def register():

    data = request.json

    name = data.get("name")
    email = data.get("email")
    password = data.get("password")

    existing_user = UserModel.find_by_email(email)

    if existing_user:
        return jsonify({
            "message": "User already exists"
        }), 400

    hashed_password = bcrypt.hashpw(
        password.encode("utf-8"),
        bcrypt.gensalt()
    )

    UserModel.create_user({
        "name": name,
        "email": email,
        "password": hashed_password
    })

    return jsonify({
        "message": "User registered successfully"
    })


# LOGIN
@auth_bp.route("/login", methods=["POST"])
def login():

    data = request.json

    email = data.get("email")
    password = data.get("password")

    user = UserModel.find_by_email(email)

    if not user:
        return jsonify({
            "message": "Invalid email"
        }), 401

    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user["password"]
    ):
        return jsonify({
            "message": "Invalid password"
        }), 401

    token = create_access_token(
        identity=email
    )

    return jsonify({
        "token": token,
        "user": {
            "name": user["name"],
            "email": user["email"]
        }
    })