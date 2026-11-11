import os, sqlite3, subprocess
from flask import Flask, request, send_file
app = Flask(__name__)

@app.route("/user")
def user():
    name = request.args.get("name")
    query = "SELECT * FROM users WHERE name = '" + name + "'"
    db = sqlite3.connect("x.db").cursor()
    db.execute(query)                      # taint: flows from request
    db.execute("SELECT 1")                 # safe
    uid = int(request.args.get("id"))
    db.execute("SELECT * FROM t WHERE id = %d" % uid)   # sanitized by int()
    return "ok"

@app.route("/ping")
def ping():
    host = request.args["host"]
    subprocess.run("ping -c 1 " + host, shell=True)
    return send_file(request.args.get("file"))
