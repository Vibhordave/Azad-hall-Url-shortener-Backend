import sys
import os
sys.path.insert(0, os.path.abspath('C:\\Users\\vibho\\OneDrive\Desktop\\Full Stack Using Flask'))
sys.path.insert(1, os.path.abspath('C:\\Users\\vibho\\OneDrive\Desktop\\Full Stack Using Flask\\src'))
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify


app = Flask(__name__)
if __name__ == '__main__':
    app.run(debug=True)

@app.route("/")
def home():
    return "Hello World!"

@app.route("/register",methods=['POST'])
def reg():
    data=request.get_json()
    try:
        print(auth.signup(User.SignUPUserSchema(username=data["username"],email=data["email"],password=data["password"])))
        return jsonify({"status":"Succesfully signed up"}),200
    except:
        return jsonify({"Sign up failed"}),400

@app.route("/login",methods=['POST'])
def login():
    data=request.get_json()
    return auth.login(User.LoginUserSchema(email=data["email"],password=data["password"]))
    # try:
        
    #     return jsonify({"status":"Succesfully signed in"}),200
    # except:
    #     return jsonify({"status":"Sign in failed"}),400
@app.route("/signout",methods=['POST'])
def logout():
    data=request.get_json()
    return auth.signout(data["id"])

@app.route("/<shorty>",methods=['GET','POST'])
def redirection(shorty):
    return urlShorty.redirect_to_url(shorty)

@app.route("/api/getShortUrl",methods=['GET','POST'])
def getshorty():
    data = request.get_json()
    return urlShorty.getShortUrl(data["long"])

@app.route("/api/getLongUrl",methods=['GET','POST'])
def getlongy():
    data = request.get_json()
    return urlShorty.getLongUrl(data["short"])

@app.route("/api/delUrl/<id>",methods=['GET','POST'])
def delUrl(id):
    return urlShorty.delUrl(id)

@app.route("/shorten",methods=['GET','POST'])
def shortenUrl():
    data=request.get_json()
    return urlShorty.convertUrl(data["long"])

    
from src.routers import auth
from src.routers import urlShorty
from src.schemas import userSchema as User
from src.schemas import sessionSchema as Session
