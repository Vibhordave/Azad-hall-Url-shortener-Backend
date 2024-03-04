from ..schemas import userSchema as User 
from ..schemas import sessionSchema as Session
from ..database.mongo import userDb,sessionDb
import jwt,bcrypt
from uuid import uuid4 as uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
router=APIRouter()

def signup(request: User.SignUPUserSchema):
    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db_user = userDb.find_one({"email": request.email.lower()})
    print("Check 1")
    if db_user is not None:
        return jsonify({"message": "User already exists", "user": None}), 400
    
    user_data = {
        "id": str(uuid()), 
        "email": request.email.lower(),
        "password": hashed_password,
        "name": request.username
    }
    print("Check 2")
    userDb.insert_one(user_data)
    print("Check 3")
    
    # Remove any non-serializable objects (e.g., sets) from the user_data dictionary
    user = {key: value for key, value in user_data.items() if not isinstance(value, set)}

    return jsonify({"message": "User created successfully.", "user": user}), 200

def signout(id):
    sessions=sessionDb.find({"id":id})
    # if len(sessions) == 0:
    #     return jsonify({"message": "User not found"}),400
    for a in sessions:
        sessionDb.delete_one({"id":a["id"]})

    return jsonify({'status': 'success'}),200

from flask import jsonify
import bcrypt

def login(payload: User.LoginUserSchema):
    db_user = userDb.find_one({'email': payload.email.lower()})
    if not db_user:
        return jsonify({"message": "User not found."}), 400

    hashed_password = db_user.get('password')

    if not hashed_password:
        return jsonify({"message": "Password not found."}), 400
    
    user_id = db_user.get("id")
    
    if not user_id:
        return jsonify({"message": "User Id not found."}), 400

    if not bcrypt.checkpw(payload.password.encode('utf-8'), hashed_password.encode('utf-8')):
        return jsonify({"message": "Incorrect Id or Password."}), 400
    
    # Remove the 'id' and 'logged_in' keys from the db_user dictionary
    session = {
        "id": user_id,
        "logged_in": 1
    }
    session_inst = {key: value for key, value in session.items() if not isinstance(value, set)}
    
    # Insert the session into the database
    sessionDb.insert_one(session_inst)
    
    # Return a JSON response indicating success
    return jsonify({"status": "success"}), 200



# Find whose session is active