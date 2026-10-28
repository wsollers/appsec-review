"""Synthetic Flask service for the appsec-review python graph-export fixture."""
import getpass
import os
import pickle
import sqlite3
import sys

import requests
from flask import Flask
from pymongo import MongoClient

app = Flask(__name__)
ALLOWED = {"alpha", "beta"}


def run_query(conn, query):
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


@app.route("/users/<name>")
def show_user(name):
    conn = sqlite3.connect("app.db")
    rows = run_query(conn, "SELECT * FROM users WHERE name = '" + name + "'")
    return str(len(rows))


@app.route("/ping/<host>")
def ping(host):
    if host in ALLOWED:
        os.system("ping -c 1 " + host)
    os.system("nslookup " + host)
    return "ok"


@app.route("/files/<filename>")
def read_file(filename):
    safe = os.path.realpath(filename)
    with open(safe) as handle:
        handle.read()
    return "read"


@app.route("/fetch/<path:url>")
def fetch(url):
    requests.get(url)
    return "fetched"


@app.route("/load/<blob>")
def load(blob):
    pickle.loads(blob)
    return "loaded"


@app.route("/search/<term>")
def search(term):
    MongoClient().db.items.find({"name": term})
    return "searched"


class Handler:
    def __init__(self, prefix):
        self.prefix = prefix

    def handle(self, value):
        return self.run(value)


class Upper(Handler):
    def run(self, value):
        return self.prefix + value.upper()


class Lower(Handler):
    def run(self, value):
        return self.prefix + value.lower()


def dispatch(handler, action, value):
    return getattr(handler, action)(value)


def main():
    conn = sqlite3.connect("app.db")
    run_query(conn, "SELECT * FROM t WHERE id = " + sys.argv[1])
    run_query(conn, "SELECT * FROM t WHERE pw = '" + getpass.getpass() + "'")
    os.system(os.environ["APP_HOOK"])
    dispatch(Upper(">"), "handle", sys.argv[2])


if __name__ == "__main__":
    main()
