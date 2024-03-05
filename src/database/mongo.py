import sys
sys.path.append('../../')
from flask import Flask
from flask_pymongo import PyMongo
from app import app

app.config["MONGO_URI"]="mongodb+srv://vibhordave03:1234@cluster0.wanrwwp.mongodb.net/Azad_Url"
db=PyMongo(app).db

userDb = db.User
sessionDb=db.Session
urlDb=db.Urls