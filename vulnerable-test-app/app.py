"""
DELIBERATELY VULNERABLE local test application.
For authorized local lab testing of the scanner ONLY. Never deploy publicly.
"""
import sqlite3
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response

app = FastAPI()
db = sqlite3.connect(":memory:", check_same_thread=False)
db.execute("CREATE TABLE products (id INTEGER, name TEXT)")
db.executemany("INSERT INTO products VALUES (?,?)", [(1, "Widget"), (2, "Gadget"), (3, "Doohickey")])


@app.get("/", response_class=HTMLResponse)
def index():
    r = HTMLResponse("""<html><body><h1>Vulnerable Test App</h1>
    <a href="/search?q=test">Search</a> <a href="/products?id=1">Products</a>
    <a href="/redirect?next=/">Redirect</a> <a href="/login">Login</a>
    <form method="POST" action="/comment"><input name="text"><input type="submit"></form>
    </body></html>""")
    r.set_cookie("sessionid", "demo-not-a-real-session")  # insecure: no Secure/HttpOnly/SameSite
    r.headers["Server"] = "VulnApp/0.1 (Python)"
    return r


@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    return f"<html><body><h2>Results for {q}</h2></body></html>"  # reflected, unencoded


@app.get("/products", response_class=HTMLResponse)
def products(id: str = "1"):
    try:
        rows = db.execute(f"SELECT id, name FROM products WHERE id = {id}").fetchall()  # SQLi by design
    except sqlite3.Error as e:
        return HTMLResponse(f"<html><body>sqlite3.OperationalError: {e}</body></html>")
    return f"<html><body>{rows}</body></html>"


@app.get("/redirect")
def redirect(next: str = "/"):
    return RedirectResponse(next)  # open redirect by design


@app.get("/login", response_class=HTMLResponse)
def login():
    return "<html><body><form method='POST' action='/login'><input name='user'><input name='pw' type='password'></form></body></html>"


@app.get("/.env")
def env():
    return Response("APP_NAME=demo\nAPI_KEY=FAKE-NOT-A-REAL-KEY\n", media_type="text/plain")
