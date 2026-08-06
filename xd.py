import os
import sqlite3
import bcrypt
import shutil
from datetime import datetime
import socketio
from fastapi import FastAPI, HTTPException, Depends, status, File, UploadFile, Form
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional, List

# --- Configuration & Initialization ---
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "wavegram.db")

# Dossiers statiques pour les médias
AVATARS_DIR = os.path.join(BASE_DIR, "static", "avatars")
UPLOADS_DIR = os.path.join(BASE_DIR, "static", "uploads")
REELS_DIR = os.path.join(BASE_DIR, "static", "reels")

for folder in [AVATARS_DIR, UPLOADS_DIR, REELS_DIR]:
    os.makedirs(folder, exist_ok=True)

app = FastAPI(title="Wavegram Complete API", version="2.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

# Socket.IO setup
sio = socketio.AsyncServer(async_mode="asgi", cors_allowed_origins="*")
socket_app = socketio.ASGIApp(sio, app)

# --- Database Setup ---
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        # Table des utilisateurs
        conn.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                status TEXT DEFAULT 'offline',
                avatar TEXT DEFAULT 'default.png',
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)
        # Table des groupes
        conn.execute("""
            CREATE TABLE IF NOT EXISTS groups (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                admin_id INTEGER,
                password TEXT,
                invite_token TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(admin_id) REFERENCES users(id)
            )
        """)
        # Table des membres de groupes
        conn.execute("""
            CREATE TABLE IF NOT EXISTS group_members (
                group_id INTEGER,
                user_id INTEGER,
                joined_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY(group_id, user_id),
                FOREIGN KEY(group_id) REFERENCES groups(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        # Table des messages (DM et Groupes)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_id INTEGER,
                receiver_id INTEGER,
                group_id INTEGER,
                content TEXT,
                media_url TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(sender_id) REFERENCES users(id),
                FOREIGN KEY(receiver_id) REFERENCES users(id),
                FOREIGN KEY(group_id) REFERENCES groups(id)
            )
        """)
        # Table des Reels
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                caption TEXT,
                video_url TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        # Table des commentaires de reels
        conn.execute("""
            CREATE TABLE IF NOT EXISTS reel_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                reel_id INTEGER,
                user_id INTEGER,
                comment TEXT,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY(reel_id) REFERENCES reels(id),
                FOREIGN KEY(user_id) REFERENCES users(id)
            )
        """)
        # Table des blocages
        conn.execute("""
            CREATE TABLE IF NOT EXISTS blocks (
                user_id INTEGER,
                blocked_id INTEGER,
                PRIMARY KEY(user_id, blocked_id),
                FOREIGN KEY(user_id) REFERENCES users(id),
                FOREIGN KEY(blocked_id) REFERENCES users(id)
            )
        """)
        conn.commit()

init_db()

# --- Pydantic Models ---
class UserRegister(BaseModel):
    username: str
    password: str

class UserLogin(BaseModel):
    username: str
    password: str

class GroupCreate(BaseModel):
    name: str
    admin_id: int
    password: Optional[str] = None

class GroupJoin(BaseModel):
    user_id: int
    password: Optional[str] = None

class ReelCreate(BaseModel):
    user_id: int
    caption: Optional[str] = None

# --- API Endpoints: Auth ---
@app.post("/api/register")
def register(user: UserRegister):
    hashed_password = bcrypt.hashpw(user.password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
    try:
        with get_db() as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (username, password) VALUES (?, ?)", (user.username, hashed_password))
            conn.commit()
            user_id = cursor.lastrowid
        return {"success": True, "user_id": user_id, "username": user.username}
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="Username already exists")

@app.post("/api/login")
def login(user: UserLogin):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE username = ?", (user.username,))
        db_user = cursor.fetchone()
        
    if not db_user or not bcrypt.checkpw(user.password.encode('utf-8'), db_user["password"].encode('utf-8')):
        raise HTTPException(status_code=401, detail="Invalid username or password")
        
    with get_db() as conn:
        conn.execute("UPDATE users SET status = 'online' WHERE id = ?", (db_user["id"],))
        conn.commit()
        
    return {"success": True, "user_id": db_user["id"], "username": db_user["username"], "avatar": db_user["avatar"]}

# --- API Endpoints: Messaging & History ---
@app.get("/api/messages/dm/{user_id}/{target_id}")
def get_dm_history(user_id: int, target_id: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM messages 
            WHERE (sender_id = ? AND receiver_id = ?) 
               OR (sender_id = ? AND receiver_id = ?)
            ORDER BY timestamp ASC
        """, (user_id, target_id, target_id, user_id))
        messages = [dict(row) for row in cursor.fetchall()]
    return {"success": True, "messages": messages}

@app.get("/api/messages/group/{group_id}")
def get_group_messages(group_id: int):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT m.*, u.username FROM messages m
            JOIN users u ON m.sender_id = u.id
            WHERE m.group_id = ?
            ORDER BY m.timestamp ASC
        """, (group_id,))
        messages = [dict(row) for row in cursor.fetchall()]
    return {"success": True, "messages": messages}

# --- API Endpoints: Groups ---
@app.post("/api/groups")
def create_group(group: GroupCreate):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO groups (name, admin_id, password) VALUES (?, ?, ?)", 
                       (group.name, group.admin_id, group.password))
        group_id = cursor.lastrowid
        # Ajouter l'admin comme membre d'office
        cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, group.admin_id))
        conn.commit()
    return {"success": True, "group_id": group_id, "name": group.name}

@app.post("/api/groups/{group_id}/join")
def join_group(group_id: int, data: GroupJoin):
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM groups WHERE id = ?", (group_id,))
        group = cursor.fetchone()
        if not group:
            raise HTTPException(status_code=404, detail="Group not found")
        if group["password"] and group["password"] != data.password:
            raise HTTPException(status_code=403, detail="Incorrect group password")
        
        try:
            cursor.execute("INSERT INTO group_members (group_id, user_id) VALUES (?, ?)", (group_id, data.user_id))
            conn.commit()
        except sqlite3.IntegrityError:
            pass # Déjà membre
            
    return {"success": True, "message": "Joined group successfully"}

# --- API Endpoints: Reels ---
@app.post("/api/reels")
async def create_reel(user_id: int = Form(...), caption: Optional[str] = Form(None), file: UploadFile = File(...)):
    filename = f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{file.filename}"
    file_path = os.path.join(REELS_DIR, filename)
    with open(file_path, "wb") as buffer:
        shutil.copyfileobj(file.file, buffer)
    
    video_url = f"/static/reels/{filename}"
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("INSERT INTO reels (user_id, caption, video_url) VALUES (?, ?, ?)", (user_id, caption, video_url))
        conn.commit()
        reel_id = cursor.lastrowid

    return {"success": True, "reel_id": reel_id, "video_url": video_url}

@app.get("/api/reels")
def get_reels():
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT r.*, u.username, u.avatar FROM reels r
            JOIN users u ON r.user_id = u.id
            ORDER BY r.created_at DESC
        """)
        reels = [dict(row) for row in cursor.fetchall()]
    return {"success": True, "reels": reels}

# --- Socket.IO Real-Time Events ---
connected_users = {}

@sio.event
async def connect(sid, environ):
    pass

@sio.event
async def disconnect(sid):
    for user_id, s in list(connected_users.items()):
        if s == sid:
            del connected_users[user_id]
            with get_db() as conn:
                conn.execute("UPDATE users SET status = 'offline' WHERE id = ?", (user_id,))
                conn.commit()
            break

@sio.event
async def register_socket(sid, data):
    user_id = data.get("user_id")
    if user_id:
        connected_users[user_id] = sid
        await sio.emit("user_status", {"user_id": user_id, "status": "online"})

@sio.event
async def send_message(sid, data):
    sender_id = data.get("sender_id")
    receiver_id = data.get("receiver_id")
    group_id = data.get("group_id")
    content = data.get("content")
    media_url = data.get("media_url")
    
    with get_db() as conn:
        cursor = conn.cursor()
        cursor.execute(
            "INSERT INTO messages (sender_id, receiver_id, group_id, content, media_url) VALUES (?, ?, ?, ?, ?)",
            (sender_id, receiver_id, group_id, content, media_url)
        )
        conn.commit()
        msg_id = cursor.lastrowid

    payload = {
        "id": msg_id,
        "sender_id": sender_id,
        "receiver_id": receiver_id,
        "group_id": group_id,
        "content": content,
        "media_url": media_url,
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    if group_id:
        await sio.emit(f"group_message_{group_id}", payload)
    elif receiver_id in connected_users:
        await sio.emit("receive_message", payload, room=connected_users[receiver_id])

@sio.event
async def typing(sid, data):
    receiver_id = data.get("receiver_id")
    if receiver_id in connected_users:
        await sio.emit("typing", data, room=connected_users[receiver_id])

# --- WebRTC Call Signaling ---
@sio.event
async def call_offer(sid, data):
    target_id = data.get("target_id")
    if target_id in connected_users:
        await sio.emit("call_offer", data, room=connected_users[target_id])

@sio.event
async def call_answer(sid, data):
    target_id = data.get("target_id")
    if target_id in connected_users:
        await sio.emit("call_answer", data, room=connected_users[target_id])

@sio.event
async def ice_candidate(sid, data):
    target_id = data.get("target_id")
    if target_id in connected_users:
        await sio.emit("ice_candidate", data, room=connected_users[target_id])

@sio.event
async def call_reject(sid, data):
    target_id = data.get("target_id")
    if target_id in connected_users:
        await sio.emit("call_reject", data, room=connected_users[target_id])
