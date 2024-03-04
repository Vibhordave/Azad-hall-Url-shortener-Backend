from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from src.routers import auth
from src.schemas import userSchema as User
from src.schemas import sessionSchema as Session

app = Flask(__name__)

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


if __name__ == '__main__':
    app.run(debug=True)
