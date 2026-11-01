"""
Safe, isolated mock React Single-Page Application (SPA) for testing ZeroTrace's
React DOM inspection, React Router navigation, controlled component input discovery,
fetch/XHR network monitoring, and SQL injection scanning without false positives.
"""
import sqlite3
from typing import Optional
from urllib.parse import parse_qs

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Safe Mock React SPA")


def get_db():
    conn = sqlite3.connect(":memory:")
    c = conn.cursor()
    c.execute("CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, category TEXT)")
    c.execute("INSERT INTO items (name, category) VALUES ('Wireless Keyboard', 'electronics')")
    c.execute("INSERT INTO items (name, category) VALUES ('USB-C Hub', 'electronics')")
    c.execute("INSERT INTO items (name, category) VALUES ('Security Playbook', 'books')")
    conn.commit()
    return conn


REACT_INDEX_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>ZeroTrace React Vulnerable Test App</title>
  <script src="https://unpkg.com/react@18/umd/react.production.min.js" crossorigin></script>
  <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js" crossorigin></script>
  <style>
    body { font-family: sans-serif; margin: 20px; background: #0f172a; color: #f8fafc; }
    nav a { margin-right: 15px; color: #38bdf8; text-decoration: none; font-weight: bold; }
    form, .form-container { background: #1e293b; padding: 20px; border-radius: 8px; margin-top: 15px; max-width: 450px; }
    label { display: block; margin-bottom: 10px; }
    input { width: 95%; padding: 8px; margin-top: 5px; border-radius: 4px; border: 1px solid #475569; background: #0f172a; color: #fff; }
    button { margin-top: 10px; padding: 8px 16px; background: #0284c7; color: #fff; border: none; border-radius: 4px; cursor: pointer; }
  </style>
</head>
<body>
  <div id="root">
    <!-- React will mount here -->
  </div>
  <script src="/static/react-app.js"></script>
</body>
</html>
"""

REACT_APP_JS = """
// Standalone React 18 SPA Component Tree with React Router-style navigation
const { useState, useEffect, createElement: e } = React;

function App() {
  const [currentPath, setCurrentPath] = useState(window.location.pathname || '/');

  useEffect(() => {
    const handleLocationChange = () => {
      setCurrentPath(window.location.pathname || '/');
    };
    window.addEventListener('popstate', handleLocationChange);
    return () => window.removeEventListener('popstate', handleLocationChange);
  }, []);

  const navigate = (path) => {
    window.history.pushState({}, '', path);
    setCurrentPath(path);
  };

  return e('div', { className: 'app-container' },
    e('header', null,
      e('h1', null, 'ZeroTrace React Security Test Application'),
      e('nav', { 'aria-label': 'Main Navigation' },
        e('a', { href: '/', onClick: (ev) => { ev.preventDefault(); navigate('/'); } }, 'Home'),
        e('a', { href: '/login', onClick: (ev) => { ev.preventDefault(); navigate('/login'); } }, 'Login'),
        e('a', { href: '/signup', onClick: (ev) => { ev.preventDefault(); navigate('/signup'); } }, 'Sign Up'),
        e('a', { href: '/search', onClick: (ev) => { ev.preventDefault(); navigate('/search'); } }, 'Search Items'),
        e('a', { href: '/dashboard', onClick: (ev) => { ev.preventDefault(); navigate('/dashboard'); } }, 'Dashboard')
      )
    ),
    e('main', null,
      currentPath === '/login' ? e(LoginForm) :
      currentPath === '/signup' ? e(SignupForm) :
      currentPath === '/search' ? e(SearchForm) :
      currentPath === '/dashboard' ? e(DashboardPage) :
      e(HomePage, { onNavigate: navigate })
    )
  );
}

function HomePage({ onNavigate }) {
  useEffect(() => {
    // Initial data fetch simulating React REST API call
    fetch('/api/search?q=welcome').catch(() => {});
  }, []);

  return e('div', null,
    e('h2', null, 'Welcome to the React Testbed'),
    e('p', null, 'This application tests React-controlled input components, router navigation, and REST APIs.')
  );
}

// React Controlled Login Form
function LoginForm() {
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [status, setStatus] = useState('');

  const handleSubmit = (ev) => {
    ev.preventDefault();
    fetch('/api/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ username, password })
    })
    .then(r => r.json())
    .then(data => setStatus('Logged in successfully'))
    .catch(() => setStatus('Login failed'));
  };

  return e('form', { onSubmit: handleSubmit, 'aria-label': 'Login Form' },
    e('h3', null, 'Sign In with Your Account'),
    e('label', null, 'Username or Email:',
      e('input', {
        type: 'text',
        name: 'username',
        id: 'username',
        placeholder: 'Enter username',
        value: username,
        onChange: (ev) => setUsername(ev.target.value)
      })
    ),
    e('label', null, 'Password:',
      e('input', {
        type: 'password',
        name: 'password',
        id: 'password',
        placeholder: 'Enter password',
        value: password,
        onChange: (ev) => setPassword(ev.target.value)
      })
    ),
    e('button', { type: 'submit' }, 'Sign In'),
    status && e('p', null, status)
  );
}

// React Controlled Signup Form
function SignupForm() {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [fullName, setFullName] = useState('');
  const [status, setStatus] = useState('');

  const handleSubmit = (ev) => {
    ev.preventDefault();
    fetch('/api/signup', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password, full_name: fullName })
    })
    .then(r => r.json())
    .then(data => setStatus('Account created'))
    .catch(() => setStatus('Signup failed'));
  };

  return e('form', { onSubmit: handleSubmit, 'aria-label': 'Registration Form' },
    e('h3', null, 'Create New Account'),
    e('label', null, 'Full Name:',
      e('input', {
        type: 'text',
        name: 'full_name',
        id: 'full_name',
        placeholder: 'Jane Doe',
        value: fullName,
        onChange: (ev) => setFullName(ev.target.value)
      })
    ),
    e('label', null, 'Email Address:',
      e('input', {
        type: 'email',
        name: 'email',
        id: 'email',
        placeholder: 'jane@example.com',
        value: email,
        onChange: (ev) => setEmail(ev.target.value)
      })
    ),
    e('label', null, 'Password:',
      e('input', {
        type: 'password',
        name: 'password',
        id: 'password',
        value: password,
        onChange: (ev) => setPassword(ev.target.value)
      })
    ),
    e('button', { type: 'submit' }, 'Create Account'),
    status && e('p', null, status)
  );
}

// React Controlled Search Form with Vulnerable & Safe SQL targets
function SearchForm() {
  const [category, setCategory] = useState('electronics');
  const [results, setResults] = useState('');

  const handleVulnerableSearch = (ev) => {
    ev.preventDefault();
    fetch('/vulnerable-sqli?category=' + encodeURIComponent(category))
      .then(r => r.text())
      .then(html => setResults(html))
      .catch(() => setResults('Error querying items'));
  };

  const handleSafeSearch = (ev) => {
    ev.preventDefault();
    fetch('/safe-endpoint?category=' + encodeURIComponent(category))
      .then(r => r.text())
      .then(html => setResults(html))
      .catch(() => setResults('Error querying items'));
  };

  return e('div', { className: 'form-container', role: 'search' },
    e('h3', null, 'Search Inventory'),
    e('form', { onSubmit: handleVulnerableSearch },
      e('label', null, 'Category Filter:',
        e('input', {
          type: 'text',
          name: 'category',
          id: 'category',
          placeholder: 'electronics',
          value: category,
          onChange: (ev) => setCategory(ev.target.value)
        })
      ),
      e('button', { type: 'submit' }, 'Search (Target: /vulnerable-sqli)'),
      e('button', { type: 'button', onClick: handleSafeSearch, style: { marginLeft: '8px', background: '#059669' } }, 'Search Safe (Target: /safe-endpoint)')
    ),
    e('div', { id: 'search-results', dangerouslySetInnerHTML: { __html: results } })
  );
}

function DashboardPage() {
  const [items, setItems] = useState([]);
  const [unauth, setUnauth] = useState(false);

  useEffect(() => {
    fetch('/api/dashboard/items')
      .then(r => {
        if (r.status === 401 || r.status === 403) {
          setUnauth(true);
        }
        return r.json();
      })
      .then(data => setItems(data.items || []))
      .catch(() => {});
  }, []);

  if (unauth) {
    return e('div', null,
      e('h2', null, 'Dashboard'),
      e('p', { style: { color: '#f87171' } }, 'Authentication required: Please sign in to view dashboard.')
    );
  }

  return e('div', null,
    e('h2', null, 'Authenticated Dashboard'),
    e('p', null, 'Welcome to the protected dashboard area.')
  );
}

// Mount the React Application
const root = ReactDOM.createRoot(document.getElementById('root'));
root.render(e(App));
"""


@app.get("/static/react-app.js")
async def static_react_app():
    return HTMLResponse(REACT_APP_JS, media_type="application/javascript")


# Backend REST API Endpoints
@app.post("/api/login")
async def api_login(request: Request):
    try:
        body = await request.json()
        username = body.get("username", "")
        return JSONResponse({"status": "success", "user": username, "token": "mock-token-xyz"})
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)


@app.post("/api/signup")
async def api_signup(request: Request):
    try:
        body = await request.json()
        email = body.get("email", "")
        return JSONResponse({"status": "created", "email": email})
    except Exception:
        return JSONResponse({"status": "error", "message": "Invalid JSON"}, status_code=400)


@app.get("/api/search")
async def api_search(q: str = ""):
    return JSONResponse({"query": q, "count": 0, "items": []})


@app.get("/api/dashboard/items")
async def api_dashboard(request: Request):
    auth = request.headers.get("authorization", "")
    cookie = request.cookies.get("session", "")
    if not auth and not cookie:
        return JSONResponse({"error": "Unauthorized", "message": "Authentication required"}, status_code=401)
    return JSONResponse({"items": ["Server 1", "Database Cluster 2", "API Gateway"]})


# Deliberately vulnerable SQL endpoint
@app.get("/vulnerable-sqli")
async def vulnerable_sqli(category: str = "electronics"):
    conn = get_db()
    c = conn.cursor()
    # Deliberate unescaped string concatenation to test SQLi detection safely
    query = f"SELECT id, name, category FROM items WHERE category = '{category}'"
    try:
        c.execute(query)
        rows = c.fetchall()
        output = "<br>".join([f"{r[1]} ({r[2]})" for r in rows])
        return HTMLResponse(f"<html><body>Items in {category}:<br>{output}</body></html>")
    except sqlite3.OperationalError as exc:
        return HTMLResponse(f"<html><body>Database OperationalError: near \"{str(exc)}\": syntax error</body></html>", status_code=500)
    finally:
        conn.close()


# Parameterized safe SQL endpoint (immune to SQLi)
@app.get("/safe-endpoint")
async def safe_endpoint(category: str = "electronics"):
    conn = get_db()
    c = conn.cursor()
    c.execute("SELECT id, name, category FROM items WHERE category = ?", (category,))
    rows = c.fetchall()
    output = "<br>".join([f"{r[1]} ({r[2]})" for r in rows])
    conn.close()
    return HTMLResponse(f"<html><body>Safe Items in {category}:<br>{output}</body></html>")


# SPA Fallback: All page routes serve the React application HTML
@app.get("/{full_path:path}")
async def spa_fallback(full_path: str):
    return HTMLResponse(REACT_INDEX_HTML)

