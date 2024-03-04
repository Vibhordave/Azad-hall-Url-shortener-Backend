from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_mail import Mail, Message
from flask_sqlalchemy import SQLAlchemy
from flask_dance.contrib.google import make_google_blueprint, google
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
from werkzeug.security import generate_password_hash, check_password_hash
import os
from src.routers import auth
from src.schemas import userSchema as User

app = Flask(__name__)

@app.route("/")
def home():
    return "Hello World!"

@app.route("/register",methods=['POST'])
def reg():
    data=request.get_json()
    return auth.signup(User.SignUPUserSchema(username=data["username"],email=data["email"],password=data["password"]))

@app.route("/login",methods=['POST'])
def login():
    data=request.get_json()
    return auth.login(User.LoginUserSchema(email=data["email"],password=data["password"]))



if __name__ == '__main__':
    app.run(debug=True)
