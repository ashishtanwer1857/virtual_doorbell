from flask import Flask,render_template,request,flash,send_file,session,url_for,redirect
import sqlite3,time
import os,shutil
import qrcode,hashlib
import secrets
import requests
from werkzeug.security import generate_password_hash,check_password_hash
from telegram import Update
from telegram.ext import (
    Updater,
    CommandHandler,
    CallbackContext
)




app= Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret")

ring_cooldown=30


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

def init_db():
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS doorbell (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            token_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS ring_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            owner_id TEXT NOT NULL,
            token_used TEXT,
            visitor_ip TEXT,
            visitor_email TEXT,
            ring_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        tg_chat_id TEXT NOT NULL
    )
    """)


    conn.commit()
    conn.close()

init_db()
def create_doorbell_for_owner(owner_id):
    token = secrets.token_urlsafe(16)
    token_hash = hash_token(token)

    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        "DELETE FROM doorbell WHERE owner_id=?",
        (owner_id,)
    )
    cursor.execute(
        "INSERT INTO doorbell (owner_id, token_hash) VALUES(?,?)",
        (owner_id, token_hash)
    )

    conn.commit()
    conn.close()

    
    return token



def generate_qr_for_owner(owner_id, token):
    domain = os.environ.get("RAILWAY_PUBLIC_DOMAIN")

    if not domain:
        raise RuntimeError("RAILWAY_PUBLIC_DOMAIN not available")

    base_url = f"https://{domain}"
    ring_url = f"{base_url}/ring/{token}"

    

    qr = qrcode.make(ring_url)
    path = f"static/owner_{owner_id}.png"
    qr.save(path)

    return f"/static/owner_{owner_id}.png"





def expose_qr_for_display(owner_id):
    src =  f"qr_codes/owner_{owner_id}_qr.png"
    dst = f"static/owner_{owner_id}_qr.png"

    if os.path.exists(src):
        shutil.copy(src, dst)
def save_ring_event(owner_id, email, ip):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO ring_history (owner_id, visitor_email, visitor_ip)
        VALUES (?, ?, ?)
        """,
        (owner_id, email, ip)
    )

    conn.commit()
    conn.close()


def can_ring_again(email, ip):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute("""
        SELECT COUNT(*) FROM ring_history
        WHERE (visitor_email = ? OR visitor_ip = ?)
        AND ring_time >= datetime('now', ?)
    """, (email, ip, f'-{ring_cooldown} seconds'))

    count = cursor.fetchone()[0]
    conn.close()

    return count == 0
def get_token_for_owner(owner_id):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT token_hash FROM doorbell WHERE owner_id=?",
        (owner_id,)
    )
    row = cursor.fetchone()
    conn.close()

    return row

def get_owner_by_token(token):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute("SELECT owner_id, token_hash FROM doorbell")
    rows = cursor.fetchall()
    conn.close()

    token_hashed = hash_token(token)

    for owner_id, token_hash in rows:
        if token_hashed == token_hash:
            return owner_id

    return None

def is_owner_email(email):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT id FROM users WHERE email=? AND role='owner'",
        (email,)
    )
    row = cursor.fetchone()
    conn.close()

    return row is not None


#Now telegram functions starts....

def telegram_start(update: Update, context: CallbackContext):
    message = update.message.text
    chat_id = update.message.chat_id

    parts = message.split()

    if len(parts) != 2:
        update.message.reply_text(
            "❌ Invalid start link.\nPlease connect Telegram from dashboard."
        )
        return

    owner_id = parts[1]

    # Save chat_id in database
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        "UPDATE users SET telegram_chat_id=? WHERE id=?",
        (chat_id, owner_id)
    )

    conn.commit()
    conn.close()

    update.message.reply_text(
        "✅ Telegram connected successfully!\nYou will now receive doorbell notifications."
    )
def start_telegram_bot():
    token = os.environ.get("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ TELEGRAM_BOT_TOKEN not set")
        return

    updater = Updater(token, use_context=True)
    dp = updater.dispatcher

    dp.add_handler(CommandHandler("start", telegram_start))

    updater.start_polling()
    print("🤖 Telegram bot started")


def send_telegram_message(chat_id, text):
    token = os.environ.get("TELEGRAM_BOT_TOKEN")

    if not token:
        print("❌ TELEGRAM_BOT_TOKEN missing")
        return

    url = f"https://api.telegram.org/bot{token}/sendMessage"

    payload = {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML"
    }

    try:
        requests.post(url, json=payload, timeout=5)
    except Exception as e:
        print("❌ Telegram send error:", e)

def get_owner_telegram_chat_id(owner_id):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT telegram_chat_id FROM users WHERE id=?",
        (owner_id,)
    )
    row = cursor.fetchone()
    conn.close()

    return row[0] if row and row[0] else None


@app.route("/")
def homepage():
    return render_template("homepage.html")
@app.route("/visitor")
def visitor():
    return render_template("scan_qr.html")
@app.route("/signup", methods=["GET", "POST"])
def signup():
    error = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("doorbell.db")
        cursor = conn.cursor()

        # check if owner already exists
        cursor.execute("SELECT id FROM users WHERE email=?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            error = "Email already registered"
        else:
            password_hash = generate_password_hash(password)
            cursor.execute(
                "INSERT INTO users (email, password_hash, role) VALUES (?, ?, ?)",
                (email, password_hash, "owner")
            )
            conn.commit()
            conn.close()
            return redirect(url_for("login"))

        conn.close()

    return render_template("signup.html", error=error)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None

    if request.method == "POST":
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("doorbell.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, password_hash FROM users WHERE email=? AND role='owner'",
            (email,)
        )
        user = cursor.fetchone()
        conn.close()

        if user and check_password_hash(user[1], password):
            owner_id = user[0]

            # session setup
            session["owner_logged_in"] = True
            session["owner_id"] = owner_id

            # 🔥 TOKEN GENERATED ONCE
            token = create_doorbell_for_owner(owner_id)

            # 🔥 QR GENERATED ONCE WITH SAME TOKEN
            qr_path = generate_qr_for_owner(owner_id, token)

            # 🔥 STORED ONCE
            session["qr_path"] = qr_path

            return redirect(url_for("dashboard"))
        else:
            error = "Invalid credentials"

    return render_template("login.html", error=error)




@app.route("/dashboard")
def dashboard():
    if not session.get("owner_logged_in"):
        return redirect(url_for("login"))

    owner_id = session["owner_id"]

    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()
    cursor.execute(
        "SELECT tg_chat_id FROM users WHERE id=?",
        (owner_id,)
    )
    row = cursor.fetchone()
    conn.close()

    telegram_connected = bool(row and row[0])

    return render_template(
        "dashboard.html",
        qr_file=session.get("qr_path"),
        telegram_connected=telegram_connected,
        owner_id=owner_id
    )




@app.route("/ring/<token>", methods=["GET", "POST"])
def ring(token):
    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM doorbell")
    count = cursor.fetchone()[0]
    conn.close()

    print("📦 Doorbell rows in DB:", count)

    owner_id = get_owner_by_token(token)
    print("🔑 Token received:", token)
    print("👤 Owner resolved:", owner_id)

    if not owner_id:
        return "❌ Invalid QR"

    if "visitor_email" not in session:
        if request.method == "POST":
            email = request.form["email"]

        # ❌ BLOCK OWNER EMAIL
            if is_owner_email(email):
                return render_template(
                    "visitor_email.html",
                    error="❌ Owner email cannot be used to ring the bell"
                )

            session["visitor_email"] = email
            return redirect(url_for("ring", token=token))

        return render_template("visitor_email.html")


    message = None

    if request.method == "POST":
        visitor_ip = request.remote_addr
        visitor_email = session["visitor_email"]

        if not can_ring_again(visitor_email, visitor_ip):
            return render_template(
                "ring.html",
                message="⏳ Please wait before ringing again"
            )

        save_ring_event(owner_id, visitor_email, visitor_ip)
        chat_id = get_owner_telegram_chat_id(owner_id)

        if chat_id:
            message = f"""
        🔔 <b>Doorbell Rang</b>

        📧 Visitor: {visitor_email}
        🌐 IP: {visitor_ip}
        🕒 Time: just now
        """
            send_telegram_message(chat_id, message)

        message = "✅ Bell rang successfully!"

    return render_template("ring.html", message=message)


@app.route("/download-qr")
def download_qr():
    if not session.get("owner_logged_in"):
        return redirect(url_for("login"))

    owner_id = session["owner_id"]
    path = f"qr_codes/owner_{owner_id}_qr.png"

    # If missing, regenerate via dashboard logic
    if not os.path.exists(path):
        return redirect(url_for("dashboard"))

    return send_file(path, as_attachment=True)


@app.route("/history")
def history():
    if not session.get("owner_logged_in"):
        return redirect(url_for("login"))

    owner_id = session["owner_id"]

    conn = sqlite3.connect("doorbell.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM ring_history WHERE owner_id=? ORDER BY ring_time DESC",
        (owner_id,)
    )
    rings = cursor.fetchall()
    conn.close()

    return render_template("history.html", rings=rings)

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


if __name__ == "__main__":
    app.run()

import threading

if __name__ == "__main__":
    threading.Thread(target=start_telegram_bot).start()
    app.run(host="0.0.0.0", port=8000)


