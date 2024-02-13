from flask import Flask, request, jsonify
from models.user import User
from database import db
from flask_login import LoginManager

app = Flask(__name__)
app.config['SECRET_KEY'] = "YOUR_SECRET_KEY"
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app()

@app.route('/login', methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    
    if username and password:
        x=3
    return jsonify({"message": "Credênciais inválidas"}), 400

@app.route("/hello", methods=["GET"])
def hello():
    return "HELLOOOOOOOOOOO!"

if __name__ == '__main__':
    app.run(debug=True)