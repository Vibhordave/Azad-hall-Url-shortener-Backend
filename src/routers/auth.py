from src.schemas import userSchema as User 
from src.schemas import sessionSchema as Session
from src.database.mongo import userDb,sessionDb
import jwt,bcrypt
from uuid import uuid4 as uuid
from fastapi import APIRouter, Depends, HTTPException, Request, status, Security
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

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
    session={
        "id": user["id"],
        "logged_in":1
    }
    await sessionDb.insert_one(session)
    await userDb.insert_one(user)
    return {"message": "User created successfully.", "user": user}

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

    
    token = jwt.encode(payload={"user_id": user_id}, key=config["JWT_KEY"], algorithm="HS256")

    return {'status': 'success', 'token': token}


security = HTTPBearer()

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Security(security)
) -> dict:
    token = credentials.credentials
    try:
        token_data = jwt.decode(token, config["JWT_KEY"], algorithms=["HS256"])
    except jwt.PyJWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    user = await User.find_one({'id': token_data["user_id"]})
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    return user