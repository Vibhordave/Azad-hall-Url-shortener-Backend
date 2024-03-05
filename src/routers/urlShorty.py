import sys
sys.path.append('../')
from database.mongo import urlDb
from uuid import uuid4 as uuid
from flask import redirect, jsonify
import hashlib

def getLongUrl(shortUrl):
    longurl=urlDb.find_one({"short":shortUrl})
    if longurl is None:
        return jsonify({"status":"Url not found"}),404
    return jsonify({"status":"success","long":longurl["long"]}),200

def getShortUrl(longUrl):
    shortUrl=urlDb.find_one({"long":longUrl})
    if shortUrl is None:
        return jsonify({"status":"Url not found"}),404
    return jsonify({"status":"success","short":shortUrl["short"]}),200

def redirect_to_url(shortUrl):
    longurl=urlDb.find_one({"short":shortUrl})
    if longurl is None:
        return jsonify({"status":"Url not found"}),404
    if not ('http://' in longurl["long"] or 'https://' in longurl["long"]):
        longurl["long"]='https://'+longurl["long"]
    
    longurl["counter"]=longurl["counter"]+1
    return redirect(longurl["long"],code=302)

def delUrl(id):
    url=urlDb.find_one({"id":id})
    if url is None:
        return jsonify({"status":"Url not found"}),404
    urlDb.delete_one({"id":url["id"]})
    return jsonify({"status":"success","Deleted_url":url["long"]}),200

def encode_base62(number):
    alphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
    base62 = ""
    while number:
        number, remainder = divmod(number, 62)
        base62 = alphabet[remainder] + base62
    return base62 or alphabet[0]



def md5_hash(data):
    md5 = hashlib.md5()
    md5.update(data.encode())
    hash_hex = md5.hexdigest()
    num=int(hash_hex,16)
    return encode_base62(num)

def convertUrl(longUrl):
    short=md5_hash(longUrl)
    if short == '0':
        return jsonify({"status":"Url Not entered"}),400
    url={
        "id":str(uuid()),
        "long":longUrl,
        "short":short,
        "counter":0
    }
    urlDb.insert_one(url)
    return jsonify({"status":"success"}),200