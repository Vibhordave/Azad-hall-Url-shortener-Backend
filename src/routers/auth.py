from src.schemas import userSchema as User 
from src.schemas import sessionSchema as Session
from src.database.mongo import userDb,sessionDb
import jwt,bcrypt
from uuid import uuid4 as uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
router=APIRouter()

async def signup(request: User.SignUPUserSchema):
    hashed_password = bcrypt.hashpw(request.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    db_user = await userDb.find_one({"email": request.email.lower()})
    
    if db_user is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User already exists.")
    
    user = {
        "id": str(uuid()), 
        "email": request.email.lower(),
        "password": hashed_password,
        "name": request.username
    }
    
    await userDb.insert_one(user)
    return jsonify({"message": "User created successfully.", "user": user}),200

async def signout(session: Session.SessionSchema):
    s_id=session.jwt_token
    ses=await sessionDb.find_one({"jwt_token":s_id})
    sessions=await sessionDb.find({"id":ses["id"]})
    if ses is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="User Not signed in.")
    for a in sessions:
        await sessionDb.delete_one({"id":a["id"]})

    return jsonify({'status': 'success'}),200

async def login(payload: User.LoginUserSchema):
    db_user = await User.find_one({'email': payload.email.lower()})
    if not db_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect email or password')

    hashed_password = db_user.get('password')
    
    if not hashed_password:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Password not found in database')
    user_id = db_user.get("id")
    
    if not user_id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='User ID not found')

    if not bcrypt.checkpw(payload.password.encode('utf-8'), hashed_password.encode('utf-8')):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail='Incorrect email or password')
    session={
        "id": user_id,
        "logged_in":1
    }
    await sessionDb.insert_one(session)
    return jsonify({'status': 'success'}),200


# Find whose session is active