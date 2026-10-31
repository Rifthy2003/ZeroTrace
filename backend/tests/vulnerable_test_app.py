"""
Safe, isolated mock application for testing crawler form discovery,
POST/GET/JSON parameter extraction, and SQL injection detection without false positives.
"""
import sqlite3
from urllib.parse import parse_qs
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Safe Mock Vulnerable App")

# In-memory SQLite database setup
def get_db():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, category TEXT)")
    c.execute("INSERT INTO items (name, category) VALUES ('Wireless Mouse', 'electronics')")
    c.execute("INSERT INTO items (name, category) VALUES ('USB Keyboard', 'electronics')")
    c.execute("INSERT INTO items (name, category) VALUES ('Security Guide', 'books')")
    conn.commit()
    return conn


@app.get("/", response_class=HTMLResponse)
async def index():
    return """
    <!DOCTYPE html>
    <html>
      <head><title>Test Target App</title></head>
      <body>
        <h1>Welcome to ZeroTrace Test Suite</h1>
        <nav>
          <a href="/search?q=test">Search Items</a>
          <a href="/vulnerable-sqli?category=electronics">Vulnerable Endpoint</a>
          <a href="/safe-endpoint?category=electronics">Safe Endpoint</a>
          <a href="/api/items">API Items</a>
        </nav>
        
        <!-- POST login form -->
        <form action="/login" method="POST">
          <label>Username: <input type="text" name="username" value="testuser" /></label>
          <label>Password: <input type="password" name="password" /></label>
          <button type="submit">Sign In</button>
        </form>

        <!-- POST search form -->
        <form action="/search-form" method="POST">
          <label>Search Query: <input type="text" name="search_term" value="laptop" /></label>
          <button type="submit">Search</button>
        </form>
      </body>
    </html>
    """


@app.get("/search", response_class=HTMLResponse)
async def search(q: str = ""):
    return f"<html><body>Search Results for: <b>{q}</b> (0 items found)</body></html>"


@app.post("/login", response_class=HTMLResponse)
async def login(request: Request):
    body = await request.body()
    data = parse_qs(body.decode("utf-8", errors="ignore"))
    username = data.get("username", [""])[0]
    return f"<html><body>Login evaluated for user: {username}</body></html>"


@app.post("/search-form", response_class=HTMLResponse)
async def search_form(request: Request):
    body = await request.body()
    data = parse_qs(body.decode("utf-8", errors="ignore"))
    search_term = data.get("search_term", [""])[0]
    return f"<html><body>POST Search Results for: {search_term}</body></html>"


@app.get("/api/items")
async def api_items():
    return JSONResponse({"item_id": 42, "category": "electronics", "status": "active"})


@app.post("/api/search-json")
async def api_search_json(request: Request):
    try:
        data = await request.json()
        keyword = data.get("keyword", "")
        return JSONResponse({"results": [keyword], "total": 1})
    except Exception:
        return JSONResponse({"results": [], "total": 0})


@app.get("/vulnerable-sqli")
async def vulnerable_sqli(category: str = "electronics"):
    """Deliberately vulnerable endpoint using string concatenation in query."""
    conn = get_db()
    c = conn.cursor()
    # Deliberately unescaped concatenation to test SQLi detection safely
    query = f"SELECT id, name, category FROM items WHERE category = '{category}'"
    try:
        c.execute(query)
        rows = c.fetchall()
        output = "<br>".join([f"{r[1]} ({r[2]})" for r in rows])
        return HTMLResponse(f"<html><body>Items in {category}:<br>{output}</body></html>")
    except sqlite3.OperationalError as exc:
        # SQLite error message exposed in response
        return HTMLResponse(f"<html><body>Database OperationalError: near \"{str(exc)}\": syntax error</body></html>", status_code=500)
    finally:
        conn.close()


@app.get("/safe-endpoint")
async def safe_endpoint(category: str = "electronics"):
    """Safe endpoint using parameterized query."""
    conn = get_db()
    c = conn.cursor()
    # Parameterized query - immune to SQL injection
    c.execute("SELECT id, name, category FROM items WHERE category = ?", (category,))
    rows = c.fetchall()
    output = "<br>".join([f"{r[1]} ({r[2]})" for r in rows])
    conn.close()
    return HTMLResponse(f"<html><body>Safe Items in {category}:<br>{output}</body></html>")
