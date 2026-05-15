from flask import Flask
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from api.auth import auth_bp
from config import JWT_SECRET_KEY

app = Flask(__name__)

app.config["JWT_SECRET_KEY"] = JWT_SECRET_KEY

jwt = JWTManager(app)

CORS(app)

# REGISTER BLUEPRINTS
app.register_blueprint(
    auth_bp,
    url_prefix="/api/auth"
)

@app.route("/")
def home():
    return {
        "message": "GuardianNode Backend Running"
    }

if __name__ == "__main__":
    app.run(debug=True)