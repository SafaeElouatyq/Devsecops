from flask import Flask, request
import sqlite3
import subprocess
import hashlib
import os
import ast

app = Flask(__name__)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE username=? AND password=?",
        (username, password)
    )

    if cursor.fetchone():
        return {"status": "success"}

    return {"status": "error"}, 401


@app.route("/ping", methods=["POST"])
def ping():
    host = request.json.get("host")
    output = subprocess.check_output(
        ["ping", "-c", "1", host],
        text=True
    )
    return {"output": output}


@app.route("/compute", methods=["POST"])
def compute():
    expression = request.json.get("expression")
    result = ast.literal_eval(expression)
    return {"result": result}


@app.route("/hash", methods=["POST"])
def hash_password():
    pwd = request.json.get("password")
    hashed = hashlib.sha256(pwd.encode()).hexdigest()
    return {"hash": hashed}


@app.route("/hello", methods=["GET"])
def hello():
    return {"message": "Secure DevSecOps API"}
