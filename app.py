from flask import Flask, render_template, request, redirect, Response
import sqlite3
from datetime import datetime
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import logging
import html
import os
from functools import wraps

app = Flask(__name__)

# 🔐 SECURE ENV CREDENTIALS
USERNAME = os.environ.get("ADMIN_USER", "admin")
PASSWORD = os.environ.get("ADMIN_PASS")

# Logging setup
logging.basicConfig(
    filename="security.log",
    level=logging.INFO,
    format="%(asctime)s - %(message)s"
)

# Rate limiting
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["10 per minute"]
)

DATABASE = "database.db"

blocked_ips = {}
profanity_count = {}

bad_words = ["badword", "shit", "fuck", "bitch"]


def init_db():
    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            content TEXT NOT NULL,
            created_at TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()


# 🔐 AUTH FUNCTIONS
def check_auth(username, password):
    return username == USERNAME and password == PASSWORD


def authenticate():
    return Response(
        "Authentication required", 401,
        {"WWW-Authenticate": 'Basic realm="Admin Logs"'}
    )


def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        auth = request.authorization
        if not auth or not check_auth(auth.username, auth.password):
            return authenticate()
        return f(*args, **kwargs)
    return decorated


@app.route("/", methods=["GET", "POST"])
@limiter.limit("5 per minute")
def index():
    ip = request.remote_addr

    # Block repeat attackers
    if ip in blocked_ips and blocked_ips[ip] >= 3:
        logging.warning(f"IP BLOCKED: {ip}")
        return "You are temporarily blocked.", 403

    if request.method == "POST":
        content = request.form.get("content", "").strip()

        if not content:
            logging.error(f"EMPTY INPUT from {ip}")
            return "Post cannot be empty.", 400

        if len(content) > 300:
            return "Post is too long.", 400

        # Profanity detection
        for word in bad_words:
            if word in content.lower():
                profanity_count[ip] = profanity_count.get(ip, 0) + 1
                logging.warning(f"PROFANITY DETECTED from {ip}: {content}")

                if profanity_count[ip] >= 3:
                    return "Blocked for repeated inappropriate content.", 403

                return "Inappropriate language detected.", 400

        # Attack pattern detection
        blocked_patterns = ["<script>", "DROP TABLE", "--", ";--"]
        for pattern in blocked_patterns:
            if pattern.lower() in content.lower():
                blocked_ips[ip] = blocked_ips.get(ip, 0) + 1
                logging.warning(f"BLOCKED INPUT from {ip}: {content}")
                return "Suspicious input detected.", 400

        # Sanitize input
        content = html.escape(content)

        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO posts (content, created_at) VALUES (?, ?)",
            (content, datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        )
        conn.commit()
        conn.close()

        logging.info(f"VALID POST from {ip}: {content}")

        return redirect("/")

    conn = sqlite3.connect(DATABASE)
    cursor = conn.cursor()
    cursor.execute("""
        SELECT content, created_at FROM posts
        WHERE datetime
