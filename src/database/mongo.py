from flask import Flask
from pymongo import MongoClient

client = MongoClient('localhost', 27017)

db = client.flask_db
userDb = db.User
sessionDb=db.Session