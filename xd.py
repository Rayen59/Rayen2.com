# server.py - Wavegram Full Server
# Run: pip install fastapi uvicorn python-socketio sqlalchemy bcrypt cloudflared

import os
import asyncio
import json
import bcrypt
import sqlite3
import aiofiles
import subprocess
import shutil
from datetime import datetime, timedelta
from typing import Optional, List, Dict, Any
from fastapi import FastAPI, HTTPException, Depends, UploadFile, File, Form, Request
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
import socketio
from pydantic import BaseModel
import uuid
import base64
import re
import random

# ============================================================
# DATABASE SETUP (SQLite with bcrypt password hashing)
# ============================================================

DB_PATH = "wavegram.db"

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db()
    # Users table
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            avatar TEXT,
            status TEXT DEFAULT 'offline',
            last_seen INTEGER,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            is_active INTEGER DEFAULT 1
        )
    ''')
    
    # Conversations (DMs)
    conn.execute('''
        CREATE TABLE IF NOT EXISTS conversations (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user1_id INTEGER NOT NULL,
            user2_id INTEGER NOT NULL,
            last_message_id INTEGER,
            updated_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE(user1_id, user2_id)
        )
    ''')
    
    # Messages
    conn.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            chat_type TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            sender_id INTEGER NOT NULL,
            msg_type TEXT NOT NULL,
            content TEXT,
            media_path TEXT,
            timestamp INTEGER DEFAULT (strftime('%s', 'now')),
            deleted INTEGER DEFAULT 0,
            edited INTEGER DEFAULT 0,
            reply_to_id INTEGER,
            forwarded_from_id INTEGER,
            FOREIGN KEY (sender_id) REFERENCES users(id)
        )
    ''')
    
    # Message reactions
    conn.execute('''
        CREATE TABLE IF NOT EXISTS message_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            message_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            UNIQUE(message_id, user_id),
            FOREIGN KEY (message_id) REFERENCES messages(id) ON DELETE CASCADE
        )
    ''')
    
    # Groups
    conn.execute('''
        CREATE TABLE IF NOT EXISTS groups (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            avatar TEXT,
            password_hash TEXT,
            invite_token TEXT UNIQUE,
            created_by INTEGER NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (created_by) REFERENCES users(id)
        )
    ''')
    
    # Group members
    conn.execute('''
        CREATE TABLE IF NOT EXISTS group_members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            group_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            role TEXT DEFAULT 'member',
            restricted_until INTEGER,
            joined_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE(group_id, user_id),
            FOREIGN KEY (group_id) REFERENCES groups(id) ON DELETE CASCADE
        )
    ''')
    
    # Group messages (use messages table with chat_type='group')
    
    # Reels
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reels (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            media_path TEXT NOT NULL,
            media_type TEXT NOT NULL,
            caption TEXT,
            timestamp INTEGER DEFAULT (strftime('%s', 'now')),
            view_count INTEGER DEFAULT 0,
            FOREIGN KEY (user_id) REFERENCES users(id)
        )
    ''')
    
    # Reel reactions
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reel_reactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            emoji TEXT NOT NULL,
            UNIQUE(reel_id, user_id),
            FOREIGN KEY (reel_id) REFERENCES reels(id) ON DELETE CASCADE
        )
    ''')
    
    # Reel comments
    conn.execute('''
        CREATE TABLE IF NOT EXISTS reel_comments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            reel_id INTEGER NOT NULL,
            user_id INTEGER NOT NULL,
            content TEXT NOT NULL,
            parent_id INTEGER,
            timestamp INTEGER DEFAULT (strftime('%s', 'now')),
            FOREIGN KEY (reel_id) REFERENCES reels(id) ON DELETE CASCADE
        )
    ''')
    
    # Blocks
    conn.execute('''
        CREATE TABLE IF NOT EXISTS blocks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            blocker_id INTEGER NOT NULL,
            blocked_id INTEGER NOT NULL,
            created_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE(blocker_id, blocked_id)
        )
    ''')
    
    # Read receipts
    conn.execute('''
        CREATE TABLE IF NOT EXISTS read_receipts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            chat_type TEXT NOT NULL,
            chat_id TEXT NOT NULL,
            last_read_message_id INTEGER,
            updated_at INTEGER DEFAULT (strftime('%s', 'now')),
            UNIQUE(user_id, chat_type, chat_id)
        )
    ''')
    
    conn.commit()
    conn.close()

init_db()

# ============================================================
# PYDANTIC MODELS
# ============================================================

class UserRegister(BaseModel):
    username: str
    email: str
    password: str

class UserLogin(BaseModel):
    email: str
    password: str

class MessageSend(BaseModel):
    chat_type: str
    target: str
    msg_type: str
    content: str
    media_path: str = ""
    client_id: str
    reply_to_id: Optional[int] = None

class GroupCreate(BaseModel):
    name: str
    password: str = ""

class GroupJoin(BaseModel):
    password: str = ""

class ReelCreate(BaseModel):
    caption: str = ""

class RoleChange(BaseModel):
    user_id: int
    role: str

class RestrictUser(BaseModel):
    user_id: int
    duration: int

# ============================================================
# FASTAPI APP
# ============================================================

app = FastAPI()

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Static files
os.makedirs("static/uploads", exist_ok=True)
os.makedirs("static/avatars", exist_ok=True)
os.makedirs("static/reels", exist_ok=True)
app.mount("/static", StaticFiles(directory="static"), name="static")

# Socket.IO server
sio = socketio.AsyncServer(
    cors_allowed_origins="*",
    async_mode="asgi",
    ping_timeout=60,
    ping_interval=25
)
socket_app = socketio.ASGIApp(sio, app)

# ============================================================
# AUTH HELPERS
# ============================================================

def hash_password(password: str) -> str:
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(password.encode('utf-8'), salt).decode('utf-8')

def verify_password(password: str, hashed: str) -> bool:
    return bcrypt.checkpw(password.encode('utf-8'), hashed.encode('utf-8'))

def generate_token():
    return base64.urlsafe_b64encode(os.urandom(32)).decode('utf-8').rstrip('=')

def get_user_by_token(token: str) -> Optional[dict]:
    if not token:
        return None
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE token = ? AND is_active = 1",
        (token,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

# Store tokens in memory (simple)
active_tokens = {}

def authenticate_user(token: str) -> dict:
    user = active_tokens.get(token)
    if not user:
        conn = get_db()
        db_user = conn.execute(
            "SELECT * FROM users WHERE token = ? AND is_active = 1",
            (token,)
        ).fetchone()
        conn.close()
        if db_user:
            user = dict(db_user)
            active_tokens[token] = user
    return user

# ============================================================
# API ENDPOINTS
# ============================================================

@app.get("/api/config")
async def get_config():
    # Try to get public URL from cloudflared
    public_url = os.environ.get("PUBLIC_URL", "")
    return {"public_base_url": public_url}

@app.post("/api/register")
async def register(data: UserRegister):
    conn = get_db()
    
    # Check existing
    existing = conn.execute(
        "SELECT id FROM users WHERE email = ? OR username = ?",
        (data.email, data.username)
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Email or username already taken")
    
    # Hash password
    hashed = hash_password(data.password)
    token = generate_token()
    
    cursor = conn.execute(
        "INSERT INTO users (username, email, password_hash, token, status, last_seen) VALUES (?, ?, ?, ?, 'online', ?)",
        (data.username, data.email, hashed, token, int(datetime.now().timestamp()))
    )
    user_id = cursor.lastrowid
    conn.commit()
    
    user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone())
    conn.close()
    
    active_tokens[token] = user
    return {"token": token, "user": {k:v for k,v in user.items() if k not in ['password_hash']}}

@app.post("/api/login")
async def login(data: UserLogin):
    conn = get_db()
    user = conn.execute(
        "SELECT * FROM users WHERE email = ? AND is_active = 1",
        (data.email,)
    ).fetchone()
    
    if not user or not verify_password(data.password, user['password_hash']):
        conn.close()
        raise HTTPException(401, "Invalid credentials")
    
    user = dict(user)
    token = generate_token()
    conn.execute(
        "UPDATE users SET token = ?, status = 'online', last_seen = ? WHERE id = ?",
        (token, int(datetime.now().timestamp()), user['id'])
    )
    conn.commit()
    conn.close()
    
    active_tokens[token] = user
    user['token'] = token
    return {"token": token, "user": {k:v for k,v in user.items() if k not in ['password_hash']}}

@app.get("/api/me")
async def get_me(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    return {"user": {k:v for k,v in user.items() if k not in ['password_hash']}}

@app.post("/api/profile")
async def update_profile(request: Request, username: Optional[str] = Form(None), avatar: Optional[UploadFile] = File(None)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    updates = []
    params = []
    
    if username:
        updates.append("username = ?")
        params.append(username)
    
    if avatar:
        ext = avatar.filename.split('.')[-1] if '.' in avatar.filename else 'jpg'
        filename = f"avatar_{user['id']}.{ext}"
        path = f"static/avatars/{filename}"
        content = await avatar.read()
        with open(path, "wb") as f:
            f.write(content)
        avatar_url = f"/static/avatars/{filename}"
        updates.append("avatar = ?")
        params.append(avatar_url)
    
    if updates:
        params.append(user['id'])
        conn.execute(
            f"UPDATE users SET {', '.join(updates)} WHERE id = ?",
            params
        )
        conn.commit()
    
    updated_user = dict(conn.execute("SELECT * FROM users WHERE id = ?", (user['id'],)).fetchone())
    conn.close()
    active_tokens[token] = updated_user
    return {"user": {k:v for k,v in updated_user.items() if k not in ['password_hash']}}

@app.post("/api/block")
async def block_user(request: Request, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    conn.execute(
        "INSERT OR IGNORE INTO blocks (blocker_id, blocked_id) VALUES (?, ?)",
        (user['id'], data['user_id'])
    )
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/unblock")
async def unblock_user(request: Request, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    conn.execute(
        "DELETE FROM blocks WHERE blocker_id = ? AND blocked_id = ?",
        (user['id'], data['user_id'])
    )
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/blocked")
async def get_blocked(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    users = conn.execute(
        "SELECT u.id, u.username, u.avatar FROM users u JOIN blocks b ON b.blocked_id = u.id WHERE b.blocker_id = ?",
        (user['id'],)
    ).fetchall()
    conn.close()
    return {"users": [dict(u) for u in users]}

@app.get("/api/block/status/{user_id}")
async def get_block_status(request: Request, user_id: int):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    i_blocked = conn.execute(
        "SELECT id FROM blocks WHERE blocker_id = ? AND blocked_id = ?",
        (user['id'], user_id)
    ).fetchone() is not None
    they_blocked = conn.execute(
        "SELECT id FROM blocks WHERE blocker_id = ? AND blocked_id = ?",
        (user_id, user['id'])
    ).fetchone() is not None
    conn.close()
    return {"i_blocked": i_blocked, "they_blocked": they_blocked}

@app.delete("/api/account")
async def delete_account(request: Request, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    # Verify password
    conn = get_db()
    db_user = conn.execute(
        "SELECT password_hash FROM users WHERE id = ?",
        (user['id'],)
    ).fetchone()
    if not db_user or not verify_password(data['password'], db_user['password_hash']):
        conn.close()
        raise HTTPException(401, "Invalid password")
    
    # Soft delete
    conn.execute(
        "UPDATE users SET is_active = 0, status = 'deleted', token = NULL WHERE id = ?",
        (user['id'],)
    )
    conn.commit()
    conn.close()
    
    # Notify via socket
    await sio.emit("account_deleted", room=f"user_{user['id']}")
    
    active_tokens.pop(token, None)
    return {"success": True}

@app.post("/api/logout")
async def logout(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if user:
        conn = get_db()
        conn.execute(
            "UPDATE users SET status = 'offline', token = NULL WHERE id = ?",
            (user['id'],)
        )
        conn.commit()
        conn.close()
        active_tokens.pop(token, None)
    return {"success": True}

# ============================================================
# USER SEARCH
# ============================================================

@app.get("/api/users/search")
async def search_users(request: Request, q: str = ""):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    query = "SELECT id, username, email, avatar, status FROM users WHERE is_active = 1 AND id != ?"
    params = [user['id']]
    if q:
        query += " AND (username LIKE ? OR email LIKE ?)"
        params.extend([f"%{q}%", f"%{q}%"])
    query += " LIMIT 50"
    
    users = conn.execute(query, params).fetchall()
    conn.close()
    return {"users": [dict(u) for u in users]}

# ============================================================
# CONVERSATIONS
# ============================================================

@app.get("/api/conversations")
async def get_conversations(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    # Get DMs
    dm_convos = conn.execute('''
        SELECT 
            c.id,
            'dm' as type,
            CASE WHEN c.user1_id = ? THEN u2.username ELSE u1.username END as name,
            CASE WHEN c.user1_id = ? THEN u2.avatar ELSE u1.avatar END as avatar,
            CASE WHEN c.user1_id = ? THEN u2.status ELSE u1.status END as status,
            CASE WHEN c.user1_id = ? THEN u2.id ELSE u1.id END as target_id,
            m.content as last_preview,
            m.msg_type as last_msg_type,
            m.timestamp as last_timestamp,
            m.sender_id as last_sender_id,
            (
                SELECT COUNT(*) FROM messages 
                WHERE chat_type = 'dm' AND chat_id = c.id 
                AND sender_id != ? AND timestamp > COALESCE(
                    (SELECT last_read_message_id FROM read_receipts 
                     WHERE user_id = ? AND chat_type = 'dm' AND chat_id = c.id), 0
                )
            ) as unread
        FROM conversations c
        JOIN users u1 ON u1.id = c.user1_id
        JOIN users u2 ON u2.id = c.user2_id
        LEFT JOIN messages m ON m.id = c.last_message_id AND m.deleted = 0
        WHERE (c.user1_id = ? OR c.user2_id = ?)
        AND u1.is_active = 1 AND u2.is_active = 1
        ORDER BY c.updated_at DESC
    ''', (user['id'], user['id'], user['id'], user['id'], user['id'], user['id'], user['id'], user['id'])).fetchall()
    
    # Get Groups
    group_convos = conn.execute('''
        SELECT 
            g.id,
            'group' as type,
            g.name,
            g.avatar,
            NULL as status,
            NULL as target_id,
            m.content as last_preview,
            m.msg_type as last_msg_type,
            m.timestamp as last_timestamp,
            m.sender_id as last_sender_id,
            gm.role,
            (
                SELECT COUNT(*) FROM messages 
                WHERE chat_type = 'group' AND chat_id = g.id 
                AND sender_id != ? AND timestamp > COALESCE(
                    (SELECT last_read_message_id FROM read_receipts 
                     WHERE user_id = ? AND chat_type = 'group' AND chat_id = g.id), 0
                )
            ) as unread
        FROM groups g
        JOIN group_members gm ON gm.group_id = g.id
        LEFT JOIN messages m ON m.id = (
            SELECT id FROM messages 
            WHERE chat_type = 'group' AND chat_id = g.id AND deleted = 0
            ORDER BY timestamp DESC LIMIT 1
        )
        WHERE gm.user_id = ?
        ORDER BY COALESCE(m.timestamp, g.created_at) DESC
    ''', (user['id'], user['id'], user['id'])).fetchall()
    
    # Format conversations
    result = []
    for c in dm_convos:
        d = dict(c)
        d['last_preview'] = format_preview(d.get('last_preview'), d.get('last_msg_type'))
        d['last_is_mine'] = d.get('last_sender_id') == user['id']
        result.append(d)
    
    for c in group_convos:
        d = dict(c)
        d['last_preview'] = format_preview(d.get('last_preview'), d.get('last_msg_type'))
        d['last_is_mine'] = d.get('last_sender_id') == user['id']
        result.append(d)
    
    conn.close()
    return {"conversations": result}

def format_preview(content, msg_type):
    if not content:
        return ""
    if msg_type == "gift":
        return "🎁 Sent a gift"
    if msg_type == "image":
        return "📷 Photo"
    if msg_type == "video":
        return "🎬 Video"
    if msg_type == "voice":
        return "🎤 Voice message"
    if msg_type == "call":
        parts = content.split(":")
        if len(parts) >= 2:
            ctype, status = parts[0], parts[1]
            return f"{'📞' if ctype == 'audio' else '🎥'} Call {status}"
    return content[:50] + ("..." if len(content) > 50 else "")

@app.get("/api/unread_total")
async def get_unread_total(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    total = conn.execute('''
        SELECT COUNT(*) as total FROM (
            SELECT id FROM messages m
            WHERE chat_type = 'dm' AND chat_id IN (
                SELECT id FROM conversations WHERE user1_id = ? OR user2_id = ?
            ) AND sender_id != ? AND timestamp > COALESCE(
                (SELECT last_read_message_id FROM read_receipts 
                 WHERE user_id = ? AND chat_type = 'dm' AND chat_id = m.chat_id), 0
            )
            UNION ALL
            SELECT id FROM messages m
            WHERE chat_type = 'group' AND chat_id IN (
                SELECT group_id FROM group_members WHERE user_id = ?
            ) AND sender_id != ? AND timestamp > COALESCE(
                (SELECT last_read_message_id FROM read_receipts 
                 WHERE user_id = ? AND chat_type = 'group' AND chat_id = m.chat_id), 0
            )
        )
    ''', (user['id'], user['id'], user['id'], user['id'], user['id'], user['id'], user['id'])).fetchone()
    conn.close()
    return {"total": total['total'] if total else 0}

# ============================================================
# MESSAGES
# ============================================================

@app.get("/api/messages/dm/{user_id}")
async def get_dm_messages(request: Request, user_id: int, limit: int = 100):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    # Get or create conversation
    conv = conn.execute('''
        SELECT id FROM conversations 
        WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)
    ''', (user['id'], user_id, user_id, user['id'])).fetchone()
    
    if not conv:
        cursor = conn.execute(
            "INSERT INTO conversations (user1_id, user2_id, updated_at) VALUES (?, ?, ?)",
            (min(user['id'], user_id), max(user['id'], user_id), int(datetime.now().timestamp()))
        )
        conv_id = cursor.lastrowid
        conn.commit()
    else:
        conv_id = conv['id']
    
    # Get messages with sender info
    messages = conn.execute('''
        SELECT m.*, u.username as sender_name, u.avatar as sender_avatar,
        (SELECT json_group_array(json_object('user_id', mr.user_id, 'emoji', mr.emoji)) 
         FROM message_reactions mr WHERE mr.message_id = m.id) as reactions_json
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.chat_type = 'dm' AND m.chat_id = ? AND m.deleted = 0
        ORDER BY m.timestamp DESC
        LIMIT ?
    ''', (str(conv_id), limit)).fetchall()
    
    messages = [dict(m) for m in messages]
    for m in messages:
        m['reactions'] = json.loads(m.get('reactions_json') or '[]')
        m.pop('reactions_json', None)
    
    # Mark as read
    if messages:
        conn.execute(
            "INSERT OR REPLACE INTO read_receipts (user_id, chat_type, chat_id, last_read_message_id, updated_at) VALUES (?, 'dm', ?, ?, ?)",
            (user['id'], str(conv_id), messages[0]['id'], int(datetime.now().timestamp()))
        )
        conn.commit()
    
    conn.close()
    return {"messages": messages}

@app.get("/api/messages/group/{group_id}")
async def get_group_messages(request: Request, group_id: int, limit: int = 100):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    # Check membership
    member = conn.execute(
        "SELECT id, role FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user['id'])
    ).fetchone()
    if not member:
        conn.close()
        raise HTTPException(403, "Not a member of this group")
    
    # Get messages
    messages = conn.execute('''
        SELECT m.*, u.username as sender_name, u.avatar as sender_avatar,
        (SELECT json_group_array(json_object('user_id', mr.user_id, 'emoji', mr.emoji)) 
         FROM message_reactions mr WHERE mr.message_id = m.id) as reactions_json
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.chat_type = 'group' AND m.chat_id = ? AND m.deleted = 0
        ORDER BY m.timestamp DESC
        LIMIT ?
    ''', (str(group_id), limit)).fetchall()
    
    messages = [dict(m) for m in messages]
    for m in messages:
        m['reactions'] = json.loads(m.get('reactions_json') or '[]')
        m.pop('reactions_json', None)
    
    # Mark as read
    if messages:
        conn.execute(
            "INSERT OR REPLACE INTO read_receipts (user_id, chat_type, chat_id, last_read_message_id, updated_at) VALUES (?, 'group', ?, ?, ?)",
            (user['id'], str(group_id), messages[0]['id'], int(datetime.now().timestamp()))
        )
        conn.commit()
    
    conn.close()
    return {"messages": messages}

@app.post("/api/messages/{message_id}/hide")
async def hide_message(request: Request, message_id: int):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    # Soft delete for user (just mark deleted, but keep for others)
    # We use deleted=1 for everyone, but we could add a user-specific hide
    conn.execute(
        "UPDATE messages SET deleted = 1 WHERE id = ? AND sender_id = ?",
        (message_id, user['id'])
    )
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/upload")
async def upload_file(request: Request, file: UploadFile = File(...)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    ext = file.filename.split('.')[-1] if '.' in file.filename else 'bin'
    filename = f"{uuid.uuid4().hex}.{ext}"
    path = f"static/uploads/{filename}"
    
    content = await file.read()
    with open(path, "wb") as f:
        f.write(content)
    
    return {"path": f"/static/uploads/{filename}"}

# ============================================================
# GROUPS
# ============================================================

@app.post("/api/groups")
async def create_group(request: Request, data: GroupCreate):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    invite_token = generate_token()
    password_hash = hash_password(data.password) if data.password else None
    
    cursor = conn.execute(
        "INSERT INTO groups (name, password_hash, invite_token, created_by) VALUES (?, ?, ?, ?)",
        (data.name, password_hash, invite_token, user['id'])
    )
    group_id = cursor.lastrowid
    
    # Add creator as admin
    conn.execute(
        "INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'admin')",
        (group_id, user['id'])
    )
    conn.commit()
    
    group = dict(conn.execute("SELECT * FROM groups WHERE id = ?", (group_id,)).fetchone())
    conn.close()
    return {"group": group}

@app.get("/api/groups/mine")
async def get_my_groups(request: Request):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    groups = conn.execute('''
        SELECT g.*, gm.role, 
        CASE WHEN g.password_hash IS NOT NULL THEN 1 ELSE 0 END as has_password
        FROM groups g
        JOIN group_members gm ON gm.group_id = g.id
        WHERE gm.user_id = ?
        ORDER BY g.created_at DESC
    ''', (user['id'],)).fetchall()
    conn.close()
    return {"groups": [dict(g) for g in groups]}

@app.get("/api/groups/{group_id}/members")
async def get_group_members(request: Request, group_id: int):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    members = conn.execute('''
        SELECT u.id as user_id, u.username, u.avatar, gm.role, gm.restricted_until
        FROM group_members gm
        JOIN users u ON u.id = gm.user_id
        WHERE gm.group_id = ? AND u.is_active = 1
        ORDER BY gm.role = 'admin' DESC, gm.role = 'moderator' DESC, u.username
    ''', (group_id,)).fetchall()
    conn.close()
    return {"members": [dict(m) for m in members]}

@app.post("/api/groups/{group_id}/role")
async def change_role(request: Request, group_id: int, data: RoleChange):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    # Check if caller is admin
    caller = conn.execute(
        "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user['id'])
    ).fetchone()
    if not caller or caller['role'] != 'admin':
        conn.close()
        raise HTTPException(403, "Only admins can change roles")
    
    # Update role
    conn.execute(
        "UPDATE group_members SET role = ? WHERE group_id = ? AND user_id = ?",
        (data.role, group_id, data.user_id)
    )
    conn.commit()
    
    # Get username for notification
    target_user = conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (data.user_id,)
    ).fetchone()
    conn.close()
    
    # Notify via socket
    await sio.emit("group_member_updated", {
        "group_id": str(group_id),
        "action": "role_changed",
        "target_id": data.user_id,
        "username": target_user['username'] if target_user else "Unknown",
        "new_role": data.role
    })
    
    return {"success": True}

@app.post("/api/groups/{group_id}/remove")
async def remove_from_group(request: Request, group_id: int, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    # Check if caller is admin
    caller = conn.execute(
        "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user['id'])
    ).fetchone()
    if not caller or caller['role'] != 'admin':
        conn.close()
        raise HTTPException(403, "Only admins can remove members")
    
    target_user_id = data.get('user_id')
    if not target_user_id:
        conn.close()
        raise HTTPException(400, "Missing user_id")
    
    # Remove member
    conn.execute(
        "DELETE FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, target_user_id)
    )
    conn.commit()
    
    target_user = conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (target_user_id,)
    ).fetchone()
    conn.close()
    
    await sio.emit("group_member_updated", {
        "group_id": str(group_id),
        "action": "removed",
        "target_id": target_user_id,
        "username": target_user['username'] if target_user else "Unknown"
    })
    
    return {"success": True}

@app.post("/api/groups/{group_id}/restrict")
async def restrict_user(request: Request, group_id: int, data: RestrictUser):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    caller = conn.execute(
        "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user['id'])
    ).fetchone()
    if not caller or caller['role'] not in ['admin', 'moderator']:
        conn.close()
        raise HTTPException(403, "Only admins and moderators can restrict users")
    
    restricted_until = int((datetime.now() + timedelta(seconds=data.duration)).timestamp())
    conn.execute(
        "UPDATE group_members SET restricted_until = ? WHERE group_id = ? AND user_id = ?",
        (restricted_until, group_id, data.user_id)
    )
    conn.commit()
    
    target_user = conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (data.user_id,)
    ).fetchone()
    conn.close()
    
    await sio.emit("group_member_updated", {
        "group_id": str(group_id),
        "action": "restricted",
        "target_id": data.user_id,
        "username": target_user['username'] if target_user else "Unknown",
        "duration": data.duration
    })
    
    return {"success": True}

@app.post("/api/groups/{group_id}/unrestrict")
async def unrestrict_user(request: Request, group_id: int, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    
    caller = conn.execute(
        "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user['id'])
    ).fetchone()
    if not caller or caller['role'] not in ['admin', 'moderator']:
        conn.close()
        raise HTTPException(403, "Only admins and moderators can unrestrict users")
    
    conn.execute(
        "UPDATE group_members SET restricted_until = NULL WHERE group_id = ? AND user_id = ?",
        (group_id, data.get('user_id'))
    )
    conn.commit()
    
    target_user = conn.execute(
        "SELECT username FROM users WHERE id = ?",
        (data.get('user_id'),)
    ).fetchone()
    conn.close()
    
    await sio.emit("group_member_updated", {
        "group_id": str(group_id),
        "action": "unrestricted",
        "target_id": data.get('user_id'),
        "username": target_user['username'] if target_user else "Unknown"
    })
    
    return {"success": True}

@app.post("/api/groups/join/{token}")
async def join_group(request: Request, token: str, data: GroupJoin):
    auth_token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(auth_token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    group = conn.execute(
        "SELECT id, password_hash FROM groups WHERE invite_token = ?",
        (token,)
    ).fetchone()
    if not group:
        conn.close()
        raise HTTPException(404, "Group not found")
    
    # Check password
    if group['password_hash'] and not verify_password(data.password, group['password_hash']):
        conn.close()
        raise HTTPException(401, "Invalid password")
    
    # Check if already member
    existing = conn.execute(
        "SELECT id FROM group_members WHERE group_id = ? AND user_id = ?",
        (group['id'], user['id'])
    ).fetchone()
    if existing:
        conn.close()
        raise HTTPException(400, "Already a member")
    
    conn.execute(
        "INSERT INTO group_members (group_id, user_id, role) VALUES (?, ?, 'member')",
        (group['id'], user['id'])
    )
    conn.commit()
    conn.close()
    return {"success": True}

@app.post("/api/groups/{group_id}/avatar")
async def update_group_avatar(request: Request, group_id: int, avatar: UploadFile = File(...)):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    member = conn.execute(
        "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
        (group_id, user['id'])
    ).fetchone()
    if not member or member['role'] != 'admin':
        conn.close()
        raise HTTPException(403, "Only admins can change group avatar")
    
    ext = avatar.filename.split('.')[-1] if '.' in avatar.filename else 'jpg'
    filename = f"group_{group_id}.{ext}"
    path = f"static/avatars/{filename}"
    content = await avatar.read()
    with open(path, "wb") as f:
        f.write(content)
    
    avatar_url = f"/static/avatars/{filename}"
    conn.execute(
        "UPDATE groups SET avatar = ? WHERE id = ?",
        (avatar_url, group_id)
    )
    conn.commit()
    conn.close()
    
    return {"avatar": avatar_url}

# ============================================================
# REELS
# ============================================================

@app.post("/api/reels")
async def create_reel(request: Request, file: UploadFile = File(...), caption: str = Form("")):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    ext = file.filename.split('.')[-1] if '.' in file.filename else 'mp4'
    filename = f"reel_{uuid.uuid4().hex}.{ext}"
    path = f"static/reels/{filename}"
    
    content = await file.read()
    with open(path, "wb") as f:
        f.write(content)
    
    media_type = "video" if file.content_type and file.content_type.startswith("video") else "image"
    media_path = f"/static/reels/{filename}"
    
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO reels (user_id, media_path, media_type, caption) VALUES (?, ?, ?, ?)",
        (user['id'], media_path, media_type, caption)
    )
    reel_id = cursor.lastrowid
    conn.commit()
    
    reel = dict(conn.execute('''
        SELECT r.*, u.username as author_name, u.avatar as author_avatar,
        (SELECT COUNT(*) FROM reel_reactions WHERE reel_id = r.id) as reaction_count
        FROM reels r
        JOIN users u ON u.id = r.user_id
        WHERE r.id = ?
    ''', (reel_id,)).fetchone())
    conn.close()
    
    return {"reel": reel}

@app.get("/api/reels")
async def get_reels(request: Request, limit: int = 50):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    reels = conn.execute('''
        SELECT r.*, u.username as author_name, u.avatar as author_avatar,
        (SELECT json_group_array(json_object('user_id', rr.user_id, 'emoji', rr.emoji))
         FROM reel_reactions rr WHERE rr.reel_id = r.id) as reactions_json,
        (SELECT COUNT(*) FROM reel_comments WHERE reel_id = r.id) as comment_count,
        EXISTS(SELECT 1 FROM reel_reactions WHERE reel_id = r.id AND user_id = ?) as has_reacted
        FROM reels r
        JOIN users u ON u.id = r.user_id
        WHERE u.is_active = 1
        ORDER BY r.timestamp DESC
        LIMIT ?
    ''', (user['id'], limit)).fetchall()
    
    result = []
    for r in reels:
        d = dict(r)
        d['reaction_counts'] = {}
        try:
            reactions = json.loads(d.pop('reactions_json', '[]'))
            for rr in reactions:
                if rr and rr.get('emoji'):
                    d['reaction_counts'][rr['emoji']] = d['reaction_counts'].get(rr['emoji'], 0) + 1
        except:
            pass
        d['my_reaction'] = None
        if d.get('has_reacted'):
            my_reaction = conn.execute(
                "SELECT emoji FROM reel_reactions WHERE reel_id = ? AND user_id = ?",
                (d['id'], user['id'])
            ).fetchone()
            if my_reaction:
                d['my_reaction'] = my_reaction['emoji']
        d['is_mine'] = d['user_id'] == user['id']
        result.append(d)
    
    conn.close()
    return {"reels": result}

@app.post("/api/reels/{reel_id}/react")
async def react_to_reel(request: Request, reel_id: int, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    emoji = data.get('emoji')
    conn = get_db()
    
    if emoji:
        conn.execute(
            "INSERT OR REPLACE INTO reel_reactions (reel_id, user_id, emoji) VALUES (?, ?, ?)",
            (reel_id, user['id'], emoji)
        )
    else:
        conn.execute(
            "DELETE FROM reel_reactions WHERE reel_id = ? AND user_id = ?",
            (reel_id, user['id'])
        )
    conn.commit()
    
    # Get counts
    reactions = conn.execute(
        "SELECT emoji, COUNT(*) as count FROM reel_reactions WHERE reel_id = ? GROUP BY emoji",
        (reel_id,)
    ).fetchall()
    conn.close()
    
    return {"reaction_counts": {r['emoji']: r['count'] for r in reactions}}

@app.post("/api/reels/{reel_id}/view")
async def view_reel(request: Request, reel_id: int):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    conn.execute(
        "UPDATE reels SET view_count = view_count + 1 WHERE id = ?",
        (reel_id,)
    )
    conn.commit()
    
    view_count = conn.execute(
        "SELECT view_count FROM reels WHERE id = ?",
        (reel_id,)
    ).fetchone()
    conn.close()
    
    return {"view_count": view_count['view_count'] if view_count else 0}

@app.delete("/api/reels/{reel_id}")
async def delete_reel(request: Request, reel_id: int):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    reel = conn.execute(
        "SELECT user_id, media_path FROM reels WHERE id = ?",
        (reel_id,)
    ).fetchone()
    if not reel:
        conn.close()
        raise HTTPException(404, "Reel not found")
    if reel['user_id'] != user['id']:
        conn.close()
        raise HTTPException(403, "Not your reel")
    
    # Delete file
    try:
        if reel['media_path']:
            os.remove(reel['media_path'].lstrip('/'))
    except:
        pass
    
    conn.execute("DELETE FROM reels WHERE id = ?", (reel_id,))
    conn.commit()
    conn.close()
    return {"success": True}

@app.get("/api/reels/{reel_id}/comments")
async def get_reel_comments(request: Request, reel_id: int):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    conn = get_db()
    comments = conn.execute('''
        SELECT c.*, u.username as author_name, u.avatar as author_avatar
        FROM reel_comments c
        JOIN users u ON u.id = c.user_id
        WHERE c.reel_id = ?
        ORDER BY c.timestamp ASC
    ''', (reel_id,)).fetchall()
    conn.close()
    return {"comments": [dict(c) for c in comments]}

@app.post("/api/reels/{reel_id}/comments")
async def add_reel_comment(request: Request, reel_id: int, data: dict):
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    user = authenticate_user(token)
    if not user:
        raise HTTPException(401, "Unauthorized")
    
    content = data.get('content', '').strip()
    if not content:
        raise HTTPException(400, "Comment content required")
    
    conn = get_db()
    cursor = conn.execute(
        "INSERT INTO reel_comments (reel_id, user_id, content) VALUES (?, ?, ?)",
        (reel_id, user['id'], content)
    )
    comment_id = cursor.lastrowid
    conn.commit()
    conn.close()
    return {"id": comment_id}

# ============================================================
# SOCKET.IO EVENTS
# ============================================================

user_rooms = {}
user_sids = {}

@sio.on('connect')
async def on_connect(sid, environ):
    print(f"Socket connected: {sid}")

@sio.on('auth')
async def on_auth(sid, data):
    token = data.get('token')
    if not token:
        await sio.disconnect(sid)
        return
    
    user = authenticate_user(token)
    if not user:
        await sio.emit('auth_error', {'error': 'Invalid token'}, room=sid)
        await sio.disconnect(sid)
        return
    
    user_sids[sid] = user['id']
    room = f"user_{user['id']}"
    await sio.enter_room(sid, room)
    user_rooms[user['id']] = room
    
    # Update status
    conn = get_db()
    conn.execute(
        "UPDATE users SET status = 'online', last_seen = ? WHERE id = ?",
        (int(datetime.now().timestamp()), user['id'])
    )
    conn.commit()
    conn.close()
    
    await sio.emit('auth_ok', {'user_id': user['id'], 'username': user['username']}, room=sid)
    print(f"User {user['username']} authenticated")

@sio.on('disconnect')
async def on_disconnect(sid):
    user_id = user_sids.get(sid)
    if user_id:
        conn = get_db()
        conn.execute(
            "UPDATE users SET status = 'offline', last_seen = ? WHERE id = ?",
            (int(datetime.now().timestamp()), user_id)
        )
        conn.commit()
        conn.close()
        user_sids.pop(sid, None)
        print(f"User {user_id} disconnected")

@sio.on('send_message')
async def on_send_message(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    chat_type = data.get('chat_type')
    target = data.get('target')
    msg_type = data.get('msg_type')
    content = data.get('content', '')
    media_path = data.get('media_path', '')
    client_id = data.get('client_id')
    reply_to_id = data.get('reply_to_id')
    
    conn = get_db()
    chat_id = target
    
    if chat_type == 'dm':
        # Get conversation
        conv = conn.execute(
            "SELECT id FROM conversations WHERE (user1_id = ? AND user2_id = ?) OR (user1_id = ? AND user2_id = ?)",
            (user_id, int(target), int(target), user_id)
        ).fetchone()
        if not conv:
            cursor = conn.execute(
                "INSERT INTO conversations (user1_id, user2_id, updated_at) VALUES (?, ?, ?)",
                (min(user_id, int(target)), max(user_id, int(target)), int(datetime.now().timestamp()))
            )
            chat_id = str(cursor.lastrowid)
            conn.commit()
        else:
            chat_id = str(conv['id'])
        
        # Check if blocked
        blocked = conn.execute(
            "SELECT id FROM blocks WHERE (blocker_id = ? AND blocked_id = ?) OR (blocker_id = ? AND blocked_id = ?)",
            (user_id, int(target), int(target), user_id)
        ).fetchone()
        if blocked:
            conn.close()
            await sio.emit('error_msg', {'error': 'Blocked'}, room=sid)
            return
    
    elif chat_type == 'group':
        # Check membership and restrictions
        member = conn.execute(
            "SELECT role, restricted_until FROM group_members WHERE group_id = ? AND user_id = ?",
            (int(target), user_id)
        ).fetchone()
        if not member:
            conn.close()
            await sio.emit('error_msg', {'error': 'Not a member'}, room=sid)
            return
        
        # Check if restricted
        if member['restricted_until'] and member['restricted_until'] > int(datetime.now().timestamp()):
            conn.close()
            await sio.emit('error_msg', {'error': 'You are restricted'}, room=sid)
            return
    
    # Insert message
    cursor = conn.execute(
        '''INSERT INTO messages 
           (chat_type, chat_id, sender_id, msg_type, content, media_path, reply_to_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (chat_type, chat_id, user_id, msg_type, content, media_path, reply_to_id)
    )
    message_id = cursor.lastrowid
    conn.commit()
    
    # Get full message with sender info
    message = dict(conn.execute('''
        SELECT m.*, u.username as sender_name, u.avatar as sender_avatar
        FROM messages m
        JOIN users u ON u.id = m.sender_id
        WHERE m.id = ?
    ''', (message_id,)).fetchone())
    message['reactions'] = []
    
    # Update conversation last message
    if chat_type == 'dm':
        conn.execute(
            "UPDATE conversations SET last_message_id = ?, updated_at = ? WHERE id = ?",
            (message_id, int(datetime.now().timestamp()), int(chat_id))
        )
    conn.commit()
    conn.close()
    
    # Broadcast to recipients
    if chat_type == 'dm':
        target_user_id = int(target)
        # Send to sender and target
        await sio.emit('new_message', message, room=f"user_{user_id}")
        await sio.emit('new_message', message, room=f"user_{target_user_id}")
    else:
        # Send to all group members
        conn2 = get_db()
        members = conn2.execute(
            "SELECT user_id FROM group_members WHERE group_id = ?",
            (int(target),)
        ).fetchall()
        conn2.close()
        for m in members:
            await sio.emit('new_message', message, room=f"user_{m['user_id']}")

@sio.on('edit_message')
async def on_edit_message(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    message_id = data.get('message_id')
    content = data.get('content')
    
    conn = get_db()
    message = conn.execute(
        "SELECT sender_id, chat_type, chat_id FROM messages WHERE id = ? AND deleted = 0",
        (message_id,)
    ).fetchone()
    if not message or message['sender_id'] != user_id:
        conn.close()
        return
    
    conn.execute(
        "UPDATE messages SET content = ?, edited = 1 WHERE id = ?",
        (content, message_id)
    )
    conn.commit()
    conn.close()
    
    await sio.emit('message_edited', {'message_id': message_id, 'content': content})

@sio.on('delete_message')
async def on_delete_message(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    message_id = data.get('message_id')
    
    conn = get_db()
    message = conn.execute(
        "SELECT sender_id, chat_type, chat_id FROM messages WHERE id = ? AND deleted = 0",
        (message_id,)
    ).fetchone()
    if not message:
        conn.close()
        return
    
    # Check if user can delete (own message or admin in group)
    can_delete = message['sender_id'] == user_id
    
    if not can_delete and message['chat_type'] == 'group':
        member = conn.execute(
            "SELECT role FROM group_members WHERE group_id = ? AND user_id = ?",
            (int(message['chat_id']), user_id)
        ).fetchone()
        if member and member['role'] in ['admin', 'moderator']:
            can_delete = True
    
    if not can_delete:
        conn.close()
        return
    
    conn.execute(
        "UPDATE messages SET deleted = 1 WHERE id = ?",
        (message_id,)
    )
    conn.commit()
    conn.close()
    
    await sio.emit('message_deleted', {'message_id': message_id})

@sio.on('react_message')
async def on_react_message(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    message_id = data.get('message_id')
    emoji = data.get('emoji')
    
    conn = get_db()
    conn.execute(
        "INSERT OR REPLACE INTO message_reactions (message_id, user_id, emoji) VALUES (?, ?, ?)",
        (message_id, user_id, emoji)
    )
    conn.commit()
    conn.close()
    
    await sio.emit('message_reacted', {'message_id': message_id, 'user_id': user_id, 'emoji': emoji})

@sio.on('forward_message')
async def on_forward_message(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    message_id = data.get('message_id')
    chat_type = data.get('chat_type')
    target = data.get('target')
    
    conn = get_db()
    original = conn.execute(
        "SELECT * FROM messages WHERE id = ? AND deleted = 0",
        (message_id,)
    ).fetchone()
    if not original:
        conn.close()
        return
    
    # Create forwarded message
    cursor = conn.execute(
        '''INSERT INTO messages 
           (chat_type, chat_id, sender_id, msg_type, content, media_path, forwarded_from_id)
           VALUES (?, ?, ?, ?, ?, ?, ?)''',
        (chat_type, target, user_id, original['msg_type'], original['content'], 
         original['media_path'], message_id)
    )
    new_id = cursor.lastrowid
    conn.commit()
    conn.close()
    
    # Broadcast
    # Simple: just send as new message
    await sio.emit('new_message', {
        'id': new_id,
        'sender_id': user_id,
        'msg_type': original['msg_type'],
        'content': original['content'],
        'media_path': original['media_path'],
        'forwarded_from_name': original.get('sender_name', 'Unknown')
    })

@sio.on('typing')
async def on_typing(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    chat_type = data.get('chat_type')
    target = data.get('target')
    
    # Broadcast typing to recipients
    if chat_type == 'dm':
        await sio.emit('typing', {'user_id': user_id}, room=f"user_{target}")
    else:
        # Broadcast to group members
        conn = get_db()
        members = conn.execute(
            "SELECT user_id FROM group_members WHERE group_id = ? AND user_id != ?",
            (int(target), user_id)
        ).fetchall()
        conn.close()
        for m in members:
            await sio.emit('typing', {'user_id': user_id}, room=f"user_{m['user_id']}")

@sio.on('mark_read')
async def on_mark_read(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    chat_type = data.get('chat_type')
    target = data.get('target')
    
    conn = get_db()
    # Get last message id
    last_msg = conn.execute(
        "SELECT id FROM messages WHERE chat_type = ? AND chat_id = ? ORDER BY timestamp DESC LIMIT 1",
        (chat_type, target)
    ).fetchone()
    
    if last_msg:
        conn.execute(
            "INSERT OR REPLACE INTO read_receipts (user_id, chat_type, chat_id, last_read_message_id, updated_at) VALUES (?, ?, ?, ?, ?)",
            (user_id, chat_type, target, last_msg['id'], int(datetime.now().timestamp()))
        )
        conn.commit()
    conn.close()

# ============================================================
# WEBRTC CALL SIGNALING
# ============================================================

@sio.on('call_offer')
async def on_call_offer(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    target = data.get('target')
    offer = data.get('offer')
    video = data.get('video', False)
    
    conn = get_db()
    target_user = conn.execute(
        "SELECT id, username, avatar FROM users WHERE id = ? AND is_active = 1",
        (target,)
    ).fetchone()
    conn.close()
    
    if not target_user:
        await sio.emit('call_error', {'error': 'User not found'}, room=sid)
        return
    
    sender = await get_user_by_id(user_id)
    
    await sio.emit('call_offer', {
        'from_user_id': user_id,
        'from_username': sender['username'] if sender else 'Unknown',
        'from_avatar': sender.get('avatar') if sender else None,
        'offer': offer,
        'video': video
    }, room=f"user_{target}")

@sio.on('call_answer')
async def on_call_answer(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    target = data.get('target')
    answer = data.get('answer')
    
    await sio.emit('call_answer', {'answer': answer}, room=f"user_{target}")

@sio.on('call_ice_candidate')
async def on_call_ice_candidate(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    target = data.get('target')
    candidate = data.get('candidate')
    
    await sio.emit('call_ice_candidate', {'candidate': candidate}, room=f"user_{target}")

@sio.on('call_reject')
async def on_call_reject(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    target = data.get('target')
    await sio.emit('call_reject', {}, room=f"user_{target}")

@sio.on('call_end')
async def on_call_end(sid, data):
    user_id = user_sids.get(sid)
    if not user_id:
        return
    
    target = data.get('target')
    await sio.emit('call_end', {}, room=f"user_{target}")

async def get_user_by_id(user_id):
    conn = get_db()
    user = conn.execute(
        "SELECT id, username, avatar FROM users WHERE id = ? AND is_active = 1",
        (user_id,)
    ).fetchone()
    conn.close()
    return dict(user) if user else None

# ============================================================
# PUBLIC URL (Cloudflared)
# ============================================================

def setup_cloudflare_tunnel():
    """Attempt to start cloudflared tunnel for public URL"""
    try:
        # Check if cloudflared is installed
        result = subprocess.run(['cloudflared', '--version'], capture_output=True)
        if result.returncode != 0:
            print("⚠️ cloudflared not installed. Install with: brew install cloudflared (macOS) or download from cloudflare.com")
            return None
        
        # Start tunnel
        print("🌐 Starting cloudflared tunnel...")
        import threading
        def run_tunnel():
            subprocess.run([
                'cloudflared', 'tunnel', '--url', 'http://localhost:8000',
                '--quiet'
            ], capture_output=True)
        
        threading.Thread(target=run_tunnel, daemon=True).start()
        return "Tunnel started. Check console for URL."
    except Exception as e:
        print(f"⚠️ Failed to start cloudflared: {e}")
        return None

# Try to setup tunnel on startup
setup_cloudflare_tunnel()

# ============================================================
# RUN SERVER
# ============================================================

if __name__ == "__main__":
    import uvicorn
    print("🚀 Wavegram Server starting on http://localhost:8000")
    print("📱 Open the HTML client in your browser")
    uvicorn.run("server:socket_app", host="0.0.0.0", port=8000, reload=True)
