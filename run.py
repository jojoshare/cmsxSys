# -*- coding: utf-8 -*- 
# @Time : 2024/6/24
# @Author : Xl
# @Site :
# @File : run.py
import cachetools
import requests
import time
import hashlib
import random
from flask import Flask, request, render_template, send_from_directory, jsonify
from urllib.parse import unquote

app = Flask(__name__)
# 创建一个TTL缓存，最大缓存500个元素，每个元素的有效期为7200秒
cache = cachetools.TTLCache(maxsize=500, ttl=7200)

#JS安全接口域名
@app.route('/MP_verify_aoiGCMJiqhDHbXzo.txt', methods=['GET'])
def getLogFile():
    try:
        return send_from_directory('', 'MP_verify_aoiGCMJiqhDHbXzo.txt') 
    except Exception as e:
        return str(e)

def get_access_token(appid, secret):
    url = f"https://api.weixin.qq.com/cgi-bin/token?grant_type=client_credential&appid={appid}&secret={secret}"
    response = requests.get(url)
    result = response.json()
    return result["access_token"]

def get_jsapi_ticket(access_token):
    url = f"https://api.weixin.qq.com/cgi-bin/ticket/getticket?access_token={access_token}&type=jsapi"
    response = requests.get(url)
    result = response.json()
    return result["ticket"]

def generate_signature(jsapi_ticket, url):
    nonceStr = ''.join(random.choice('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789') for _ in range(16))
    timestamp = int(time.time())
    time_struct = time.localtime(timestamp)
    formatted_time = time.strftime("%Y-%m-%d %H:%M:%S", time_struct)
    print("formatted_time:{},access_token:{},jsapi_ticket:{}.".format(formatted_time, cache["access_token"],cache["jsapi_ticket"]))
    raw_string = f"jsapi_ticket={jsapi_ticket}&noncestr={nonceStr}&timestamp={timestamp}&url={url}"
    signature = hashlib.sha1(raw_string.encode('utf-8')).hexdigest()
    return {"timestamp": timestamp, "nonceStr": nonceStr, "signature": signature}

@app.route('/')
def index(): 
    return render_template('index.html')

@app.route('/signature', methods=['POST'])
def signature():
    appid = "wxc6093abfe2c80421"
    secret = "83f61095a9ed140522fcb4aabb51d385"
    # 检查缓存中是否已经有access_token和jsapi_ticket
    if "access_token" in cache:
        access_token = cache["access_token"]
    else:
        access_token = get_access_token(appid, secret)
        cache["access_token"] = access_token
    
    if "jsapi_ticket" in cache:
        jsapi_ticket = cache["jsapi_ticket"]
    else:
        jsapi_ticket = get_jsapi_ticket(access_token)
        cache["jsapi_ticket"] = jsapi_ticket
    # 获取当前页面的URL
    url = unquote(request.form['url'])
    signature_info = generate_signature(jsapi_ticket, url)
    print("signature_info:", signature_info)
    return jsonify({'signature_info':signature_info})
    
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8002, dubug=True)